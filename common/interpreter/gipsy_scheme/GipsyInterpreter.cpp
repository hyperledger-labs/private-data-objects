/* Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <ctype.h>

#include <exception>
#include <string>
#include <map>

#include "packages/base64/base64.h"
#include "crypto.h"
#include "error.h"
#include "pdo_error.h"
#include "types.h"
#include "log.h"

#include "scheme-private.h"

#include "GipsyInterpreter.h"
#include "SchemeExtensions.h"

#include "safe_malloc.h"
#include "package.h"
#include "timer.h"
#include "zero.h"

namespace pc = pdo::contracts;
namespace pe = pdo::error;
namespace pstate = pdo::state;

#define car(p)          ((p)->_object._cons._car)
#define cdr(p)          ((p)->_object._cons._cdr)
#define caar(p)          car(car(p))
#define cadr(p)          car(cdr(p))
#define cdar(p)          cdr(car(p))
#define cddr(p)          cdr(cdr(p))
#define cadar(p)         car(cdr(car(p)))
#define caddr(p)         car(cdr(cdr(p)))
#define cdaar(p)         cdr(car(car(p)))
#define cadaar(p)        car(cdr(car(car(p))))
#define cadddr(p)        car(cdr(cdr(cdr(p))))
#define cddddr(p)        cdr(cdr(cdr(cdr(p))))
#define symprop(p)	cdr(p)

#define strvalue(p)      ((p)->_object._string._svalue)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pc::ContractInterpreter* CreateGipsyInterpreter(void)
{
    return new GipsyInterpreter();
}

extern "C" {

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void SchemeLog(unsigned int level, const char *msg, const int value)
{
    SAFE_LOG(level, "%s; %d", msg, value);
}

}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void clear_output_buffer(scheme *sc)
{
    port *pt = sc->outport->_object._port;
    Zero(pt->rep.string.start, pt->rep.string.past_the_end - pt->rep.string.start);

    pt->rep.string.curr = pt->rep.string.start;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void copy_output_buffer(
    scheme *sc,
    ByteArray& output
    )
{
    port *pt = sc->outport->_object._port;
    size_t s = pt->rep.string.curr - pt->rep.string.start;

    output.resize(pt->rep.string.curr - pt->rep.string.start + 1, 0);
    memcpy_s(output.data(), output.size(), pt->rep.string.start, s);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static std::string report_interpreter_error(
    scheme *sc,
    const char* message,
    std::string error_msg
    )
{
    port *pt = sc->outport->_object._port;

    error_msg = message;
    error_msg.append("; ");
    error_msg.append(pt->rep.string.start);

    return error_msg;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void gipsy_put_property_p(
    scheme *sc,
    const char* symbol,
    const char* property,
    pointer pvalue
    )
{
    pointer psymbol, pproperty, x;

    // add the creator property to the :contract symbol
    psymbol = mk_symbol(sc, symbol);
    pe::ThrowIfNull(psymbol, "unable to find/create symbol");

    pproperty = mk_symbol(sc, property);
    pe::ThrowIfNull(pproperty, "unable to find/create property");

    // find the symbol and update it
    for (x = symprop(psymbol); x != sc->NIL; x = cdr(x))
    {
        if (caar(x) == pproperty) break;
    }

    if (x != sc->NIL)
        cdar(x) = pvalue;
    else
    {
        pointer s1 = cons(sc, pproperty, pvalue);
        pe::ThrowIf<pe::RuntimeError>(sc->no_memory, "failure to put property");

        pointer s2 = cons(sc, s1, symprop(psymbol));
        pe::ThrowIf<pe::RuntimeError>(sc->no_memory, "failure to put property");

        symprop(psymbol) = s2;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void gipsy_put_property(
    scheme *sc,
    const char* symbol,
    const char* property,
    const char* value
    )
{
    pointer pvalue = mk_string(sc, value);
    pe::ThrowIfNull(pvalue, "unable to create string for property");

    gipsy_put_property_p(sc, symbol, property, pvalue);
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static pointer gipsy_get_property(
    scheme *sc,
    const char* symbol,
    const char* property
    )
{
    pointer psymbol = scheme_find_symbol(sc, symbol);
    pe::ThrowIf<pe::RuntimeError>(
        psymbol == sc->NIL,
        "missing symbol");

    pointer pproperty = scheme_find_symbol(sc, property);
    pe::ThrowIf<pe::RuntimeError>(
        pproperty == sc->NIL,
        "missing property");

    pointer x;
    for (x = symprop(psymbol); x != sc->NIL; x = cdr(x)) {
        if (caar(x) == pproperty) break;
    }

    if (x != sc->NIL)
        return cdar(x);

    return(sc->NIL);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void gipsy_write_to_buffer(
    scheme *sc,
    pointer value,
    ByteArray& output
    )
{
    clear_output_buffer(sc);

    pointer writesym = scheme_find_symbol(sc, "write");
    pe::ThrowIf<pe::RuntimeError>(writesym == sc->NIL, "unable to find write function symbol");

    pointer writefn = cdr(scheme_find_symbol_value(sc, sc->envir, writesym));
    pe::ThrowIf<pe::RuntimeError>(writefn == sc->NIL, "unable to find write function definition");

    scheme_call(sc, writefn, cons(sc, value, sc->NIL));
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "failed to write expression to buffer");

    copy_output_buffer(sc, output);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::Finalize(void)
{
    if (interpreter_ == NULL)
        return;

    scheme* sc = interpreter_;
    scheme_set_external_data(sc, NULL);
    scheme_deinit(sc);
    pc::safe_free_for_scheme(sc);

    pc::reset_safe_memory_allocator();

    interpreter_ = NULL;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GipsyInterpreter::~GipsyInterpreter(void)
{
    Finalize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::Initialize(void)
{
    if (interpreter_ != NULL)
        return;

    interpreter_ = scheme_init_new_custom_alloc(pc::safe_malloc_for_scheme, pc::safe_free_for_scheme, pc::safe_realloc_for_scheme);
    pe::ThrowIfNull(interpreter_, "failed to create the gipsy scheme interpreter");

    /* ---------- Create the interpreter ---------- */
    scheme* sc = interpreter_;

    /* ---------- Force all output to a string ---------- */
    // it would be nice to be able to prep the size of the
    // string for the state; we could set it to the size of
    // the incoming state plus some to avoid copies when the
    // size grows
    scheme_set_output_port_string(sc, NULL, NULL);

    /* ---------- Load extensions ---------- */
    scheme_load_extensions(sc);

    /* ---------- Load the base environment ---------- */
    scheme_load_string(sc, (const char *)packages_package_scm, packages_package_scm_len);
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "failed to load the gipsy initialization package");

    /* ---------- Reserve extra space in preparation for the contract ---------- */
    pointer p = sc->vptr->reserve_cells(sc, CELL_SEGSIZE * 2);
    pe::ThrowIf<pe::RuntimeError>(p == sc->NIL, "insufficient memory for initialization");

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (initial); segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GipsyInterpreter::GipsyInterpreter(void)
{
    Initialize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::save_dependencies(
    map<string,string>& outDependencies
    )
{
    scheme* sc = interpreter_;

    pointer dlist = gipsy_get_property(sc, ":ledger", "dependencies");
    if (is_pair(dlist)) {
        for ( ; dlist != sc->NIL; dlist = cdr(dlist)) {
            pointer dep = car(dlist);
            pe::ThrowIf<pe::ValueError>(
                is_pair(dep) == 0 || is_pair(cdr(dep)) == 0,
                "malformed dependency; dependency must be an alist");

            pointer contractid = car(dep);
            pointer statehash = cadr(dep);
            pe::ThrowIf<pe::ValueError>(
                is_string(contractid) == 0 || is_string(statehash) == 0,
                "malformed dependency; dependency must be a pair of strings");

            outDependencies[strvalue(contractid)] = strvalue(statehash);
        }
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::load_contract_code(
    const pc::ContractCode& inContractCode
    )
{
    scheme* sc = interpreter_;

    /* ---------- Load contract code ---------- */
    scheme_load_string(sc, inContractCode.Code.c_str(), inContractCode.Code.size());
    pe::ThrowIf<pe::ValueError>(
        sc->retcode != 0,
        report_interpreter_error(sc, "failed to load the contract code", error_msg_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::load_message(
    const pc::ContractMessage& inMessage
    )
{
    scheme* sc = interpreter_;

    if (! inMessage.Message.empty())
    {
        /* --------------- Load the message --------------- */

        // load string evals the string in a safe environment,
        // any definitions made or modified are thrown away
        scheme_safe_load_string(sc, inMessage.Message.c_str(), inMessage.Message.size());
        pe::ThrowIf<pe::ValueError>(
            sc->retcode != 0,
            report_interpreter_error(sc, "failed to load the message", error_msg_).c_str());

        /* message must be a list with at least the method as a parameter */
        pointer mptr = sc->value;
        pe::ThrowIf<pe::ValueError>(
            mptr == sc->EOF_OBJ,
            "incomplete message");

        pe::ThrowIf<pe::ValueError>(
            list_length(sc, mptr) < 1,
            "badly formed message, must be a list");

        pe::ThrowIf<pe::ValueError>(
            is_symbol(car(mptr)) == 0,
            "badly formed message, first element must be a method");

        pointer sptr = mk_symbol(sc, "_message");
        pe::ThrowIfNull(sptr, "unable to create the _message symbol");

        scheme_define(sc, sc->global_env, sptr, mptr);
    }
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::load_contract_state(
    const ByteArray& inIntrinsicState
    )
{
    scheme* sc = interpreter_;

    if (inIntrinsicState.size() > 0)
    {
        /* ---------- Load contract state ---------- */
        scheme_load_string(sc, reinterpret_cast<const char*>(inIntrinsicState.data()), inIntrinsicState.size());
        pe::ThrowIf<pe::RuntimeError>(
            sc->retcode != 0,
            "failed to load the contract state");

        pointer sptr = mk_symbol(sc, "_instance");
        pe::ThrowIfNull(sptr, "unable to create the _instance symbol");

        scheme_define(sc, sc->global_env, sptr, sc->value);
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::save_contract_state(
    ByteArray& outIntrinsicState
    )
{
    scheme* sc = interpreter_;

    pointer instance = scheme_find_symbol(sc, "_instance");
    pe::ThrowIf<pe::RuntimeError>(instance == sc->NIL, "unable to find contract instance");

    pointer serialfn = scheme_find_symbol(sc, "serialize-instance");
    pe::ThrowIf<pe::RuntimeError>(serialfn == sc->NIL, "unable to find serialize function");

    pointer expr, rexpr;
    expr = cons(sc, instance, sc->NIL);
    pe::ThrowIf<pe::RuntimeError>(sc->no_memory, "out of memory, save_contract_state");

    expr = cons(sc, serialfn, expr);
    pe::ThrowIf<pe::RuntimeError>(sc->no_memory, "out of memory, save_contract_state");

    rexpr = scheme_eval(sc, expr);
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "state serialization failed");

    outIntrinsicState.resize(0);
    gipsy_write_to_buffer(sc, rexpr, outIntrinsicState);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::create_initial_contract_state(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    pdo::state::Basic_KV_Plus& inoutContractState
    )
{
    scheme* sc = interpreter_;
    pe::ThrowIfNull(sc, "interpreter has not been initialized");

    // the message is not currently used though we should consider
    // how it can be implemented, throug the create-object-instance fn
    // this->load_message(inMessage);
    try {
        this->load_contract_code(inContractCode);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("load contract code");
        throw;
    }

    // connect the key value store to the interpreter, i do not believe
    // there are any security implications for hooking it up at this point
    scheme_set_external_data(sc, &inoutContractState);

    pointer _class = scheme_find_symbol(sc, inContractCode.Name.c_str());
    pe::ThrowIf<pe::ValueError>(
        _class == sc->NIL,
        "malformed contract; unable to locate the contract class");

    pointer _funcsym = scheme_find_symbol(sc, "create-object-instance");
    pe::ThrowIf<pe::ValueError>(
        _funcsym == sc->NIL,
        "malformed contract; unable to locate create-object-instance function");

    pointer _function = scheme_find_symbol_value(sc, sc->envir, _funcsym);
    pe::ThrowIf<pe::ValueError>(
        _funcsym == sc->NIL,
        "malformed contract; create-object-instance function is nil");

    /* --------------- Assign the symbol values --------------- */
    pointer rexpr;
    try  {
        gipsy_put_property(sc, ":message", "originator", inMessage.OriginatorID.c_str());
        gipsy_put_property_p(sc, ":ledger", "dependencies", sc->NIL);
        gipsy_put_property(sc, ":contract", "id", ContractID.c_str());
        gipsy_put_property(sc, ":contract", "creator", CreatorID.c_str());

        rexpr = scheme_call(sc, cdr(_function), cons(sc, _class, sc->NIL));
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("create initial contract instance");
        throw;
    }

    pe::ThrowIf<pe::ValueError>(
        sc->retcode != 0,
        report_interpreter_error(sc, "failed to create contract instance", error_msg_).c_str());

    scheme_define(sc, sc->global_env, mk_symbol(sc, "_instance"), rexpr);

    // this should not be necessary, but lets make sure the interpreter
    // doesn't have any carry over
    scheme_set_external_data(sc, NULL);

    ByteArray intrinsic_state(0);
    try {
        this->save_contract_state(intrinsic_state);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("serialize initial contract state");
        throw;
    }

    pe::ThrowIf<pe::ValueError>(MAX_STATE_SIZE < intrinsic_state.size(), "intrinsic state size exceeds maximum");

    try {
        ByteArray k(intrinsic_state_key_.begin(), intrinsic_state_key_.end());
        inoutContractState.PrivilegedPut(k, intrinsic_state);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("save initial contract state");
        throw;
    }

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (initialize contract): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::send_message_to_contract(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    const pdo::state::StateBlockId& inContractStateHash,
    pdo::state::Basic_KV_Plus& inoutContractState,
    bool& outStateChangedFlag,
    std::map<std::string,std::string>& outDependencies,
    std::string& outMessageResult
    )
{
    scheme* sc = interpreter_;
    pe::ThrowIfNull(sc, "interpreter has not been initialized");

    //the hash is the hash of the encrypted state, in our case it's the root hash given in input
    const Base64EncodedString state_hash = ByteArrayToBase64EncodedString(inContractStateHash);

    try {
        this->load_message(inMessage);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("load message");
        throw;
    }

    try {
        this->load_contract_code(inContractCode);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("load contract code");
        throw;
    }

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (code loaded): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);

    // connect the key value store to the interpreter, i do not believe
    // there are any security implications for hooking it up at this point
    scheme_set_external_data(sc, &inoutContractState);

    try {
        //Convention: we use the "IntrinsicState" key to store the value
        ByteArray k(intrinsic_state_key_.begin(), intrinsic_state_key_.end());
        ByteArray intrinsic_state(inoutContractState.PrivilegedGet(k));

        this->load_contract_state(intrinsic_state);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("load intrinsic state");
        throw;
    }

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (state loaded): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);

    /* this might not be the most obvious way to invoke the send function
       but this method is used to ensure that the message is not evaluated
       again with the contract context active */
    pointer rexpr;

    try {
        /* --------------- Assign the symbol values --------------- */
        gipsy_put_property(sc, ":message", "originator", inMessage.OriginatorID.c_str());
        gipsy_put_property_p(sc, ":ledger", "dependencies", sc->NIL);
        gipsy_put_property(sc, ":contract", "creator", CreatorID.c_str());
        gipsy_put_property(sc, ":contract", "state", state_hash.c_str());
        gipsy_put_property(sc, ":contract", "id", ContractID.c_str());
        gipsy_put_property_p(sc, ":method", "immutable", sc->NIL);

        pointer _message = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "_message"));
        pointer _instance = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "_instance"));
        pointer sendfn = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "send"));

        rexpr = scheme_call(sc, cdr(sendfn), cons(sc, cdr(_instance), cdr(_message)));
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("evaluate contract method");
        throw;
    }

    pe::ThrowIf<pe::ValueError>(
        sc->retcode < 0,
        report_interpreter_error(sc, "method evaluation failed", error_msg_).c_str());

    try {
        this->save_dependencies(outDependencies);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("save dependencies");
        throw;
    }

    /* write the result into the result buffer */
    try {
        ByteArray result(0);
        gipsy_write_to_buffer(sc, rexpr, result);
        outMessageResult = ByteArrayToString(result);
    }
    catch (std::exception& e) {
        SAFE_LOG_EXCEPTION("save contract result");
        throw;
    }

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (method invoked): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);

    // this should not be necessary, but lets make sure the interpreter
    // doesn't have any carry over
    scheme_set_external_data(sc, NULL);

    // save the state
    pointer _immutable = gipsy_get_property(sc, ":method", "immutable");
    if (_immutable == sc->NIL) {
        // serialize
        ByteArray intrinsic_state(0);
        try {
            this->save_contract_state(intrinsic_state);
        }
        catch (std::exception& e) {
            SAFE_LOG_EXCEPTION("serialize contract state");
            throw;
        }

        pe::ThrowIf<pe::ValueError>(MAX_STATE_SIZE < intrinsic_state.size(), "intrinsic state size exceeds maximum");

        try {
            ByteArray k(intrinsic_state_key_.begin(), intrinsic_state_key_.end());
            inoutContractState.PrivilegedPut(k, intrinsic_state);
        }
        catch (std::exception& e) {
            SAFE_LOG_EXCEPTION("save intrinsic state");
            throw;
        }

        outStateChangedFlag = true;
    }
    else
    {
        //leave the intrinsic state already in the kv
         outStateChangedFlag = false;
    }

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (send to contract): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);
}
