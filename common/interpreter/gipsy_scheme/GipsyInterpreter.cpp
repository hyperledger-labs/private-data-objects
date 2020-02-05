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

//#include "scheme-private.h"

#include "InvocationHelpers.h"
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
const std::string GipsyInterpreter::identity_ = "gipsy";

std::string pdo::contracts::GetInterpreterIdentity(void)
{
    return GipsyInterpreter::identity_;
}

pc::ContractInterpreter* pdo::contracts::CreateInterpreter(void)
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
const char* GipsyInterpreter::report_interpreter_error(
    scheme *sc,
    const char* message,
    const char* error
    )
{
    port *pt = sc->outport->_object._port;

    error_msg_ = message;
    if (error == NULL)
    {
        const char* e = pt->rep.string.start;
        if (strnlen(e, 1) > 0)
        {
            error_msg_.append("; ");
            error_msg_.append(e);
        }
    }
    else
    {
        if (strnlen(error, 1) > 0)
        {
            error_msg_.append("; ");
            error_msg_.append(error);
        }
    }

    return error_msg_.c_str();
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

    interpreter_ = scheme_init_new_custom_alloc(
        pc::safe_malloc_for_scheme,
        pc::safe_free_for_scheme,
        pc::safe_realloc_for_scheme);
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
        report_interpreter_error(sc, "failed to load the gipsy initialization package"));

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
void GipsyInterpreter::load_contract_code(
    const pc::ContractCode& inContractCode
    )
{
    scheme* sc = interpreter_;

    /* ---------- Load contract code ---------- */
    scheme_load_string(sc, inContractCode.Code.c_str(), inContractCode.Code.size());
    pe::ThrowIf<pe::ValueError>(
        sc->retcode != 0,
        report_interpreter_error(sc, "failed to load the contract code"));
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

    this->load_contract_code(inContractCode);

    // connect the key value store to the interpreter, i do not believe
    // there are any security implications for hooking it up at this point
    scheme_set_external_data(sc, &inoutContractState);

    // serialize the environment parameter for the method
    pstate::StateBlockId initialStateHash;
    initialStateHash.assign(initialStateHash.size(), 0); // this is probably not necessary

    std::string env;
    pc::create_invocation_environment(ContractID, CreatorID, inContractCode, inMessage, initialStateHash, env);

    // find the **initialize** symbol
    pointer _initialize_symbol = scheme_find_symbol(sc, "**initialize**");
    pe::ThrowIf<pe::ValueError>(
        _initialize_symbol == sc->NIL || sc->retcode != 0,
        "misconfigured enclave, missing initialize function");

    pointer _initialize_entry_point = scheme_find_symbol_value(sc, sc->envir, _initialize_symbol);
    pe::ThrowIf<pe::ValueError>(
        _initialize_entry_point == sc->NIL
        || sc->retcode != 0
        || ! sc->vptr->is_closure(cdr(_initialize_entry_point)),
        "misconfigured enclave, malformed initialize function");

    pointer arglist;
    pointer _environment = sc->vptr->mk_string(sc, env.c_str());
    pe::ThrowIf<pe::ValueError>(
        _environment == sc->NIL || sc->retcode != 0,
        "failed to initialize interpreter environment");

    arglist = cons(sc, _environment, sc->NIL);
    pe::ThrowIf<pe::ValueError>(
        arglist == sc->NIL || sc->retcode != 0,
        "interpreter error creating invocation request");

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (code loaded): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);

    pointer rexpr;
    rexpr = scheme_call(sc, cdr(_initialize_entry_point), arglist);
    pe::ThrowIf<pe::ValueError>(
        sc->retcode != 0,
        report_interpreter_error(sc, "failed to create contract instance"));

    pe::ThrowIf<pe::ValueError>(
        ! sc->vptr->is_string(rexpr),
        report_interpreter_error(sc, "unexpected return type"));

    bool status;
    std::string outMessageResult;
    bool outStateChangedFlag;
    std::map<std::string,std::string> outDependencies;
    pc::parse_invocation_response(strvalue(rexpr), outMessageResult, status, outStateChangedFlag, outDependencies);
    pe::ThrowIf<pe::ValueError>(
        ! status,
        report_interpreter_error(sc, "operation failed", outMessageResult.c_str()));

    // this should not be necessary, but lets make sure the interpreter
    // doesn't have any carry over
    scheme_set_external_data(sc, NULL);

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

    // serialize the environment parameter for the method
    std::string env;
    pc::create_invocation_environment(ContractID, CreatorID, inContractCode, inMessage, inContractStateHash, env);

    // find the **dispatch** symbol
    pointer _dispatch_symbol = scheme_find_symbol(sc, "**dispatch**");
    pe::ThrowIf<pe::ValueError>(
        _dispatch_symbol == sc->NIL || sc->retcode != 0,
        "misconfigured enclave, missing dispatch function");

    pointer _dispatch_entry_point = scheme_find_symbol_value(sc, sc->envir, _dispatch_symbol);
    pe::ThrowIf<pe::ValueError>(
        _dispatch_entry_point == sc->NIL
        || sc->retcode != 0
        || ! sc->vptr->is_closure(cdr(_dispatch_entry_point)),
        "misconfigured enclave, malformed dispatch function");

    pointer arglist;
    pointer _invocation = sc->vptr->mk_string(sc, inMessage.Message.c_str());
    pe::ThrowIf<pe::ValueError>(
        _invocation == sc->NIL || sc->retcode != 0,
        "failed to initialize invocation request");

    arglist = cons(sc, _invocation, sc->NIL);
    pe::ThrowIf<pe::ValueError>(
        arglist == sc->NIL || sc->retcode != 0,
        "interpreter error creating invocation request");

    pointer _environment = sc->vptr->mk_string(sc, env.c_str());
    pe::ThrowIf<pe::ValueError>(
        _environment == sc->NIL || sc->retcode != 0,
        "failed to initialize interpreter environment");

    arglist = cons(sc, _environment, arglist);
    pe::ThrowIf<pe::ValueError>(
        arglist == sc->NIL || sc->retcode != 0,
        "interpreter error creating invocation request");

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (state loaded): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);

    pointer rexpr;
    rexpr = scheme_call(sc, cdr(_dispatch_entry_point), arglist);
    pe::ThrowIf<pe::ValueError>(
        sc->retcode < 0 ,
        report_interpreter_error(sc, "method evaluation failed", ""));

    pe::ThrowIf<pe::ValueError>(
        ! sc->vptr->is_string(rexpr),
        report_interpreter_error(sc, "unexpected return type"));

    bool status;
    pc::parse_invocation_response(strvalue(rexpr), outMessageResult, status, outStateChangedFlag, outDependencies);
    pe::ThrowIf<pe::ValueError>(
        ! status,
        report_interpreter_error(sc, "method evaluation failed", outMessageResult.c_str()));

    // this should not be necessary, but lets make sure the interpreter
    // doesn't have any carry over
    scheme_set_external_data(sc, NULL);

    SAFE_LOG(PDO_LOG_DEBUG,"interpreter memory used (method invoked): segments=%d, free cells=%d, gcs=%d",
             sc->last_cell_seg+1, sc->fcells, sc->gc_calls);
}
