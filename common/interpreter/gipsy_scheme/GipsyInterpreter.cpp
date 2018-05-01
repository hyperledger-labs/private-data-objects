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

#include <string>
#include <map>

#include "crypto.h"
#include "error.h"
#include "pdo_error.h"
#include "types.h"

#include "scheme-private.h"

#include "GipsyInterpreter.h"
#include "SchemeExtensions.h"

#include "init-package.h"
#include "catch-package.h"
#include "oops-package.h"

#include "zero.h"

namespace pc = pdo::contracts;
namespace pe = pdo::error;

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
extern void Log(
    int         level,
    const char* fmt,
    ...
    );

std::map<uint64_t, size_t> safe_malloc_map;


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void *safe_malloc_for_scheme(size_t request)
{
    void *ptr = malloc(request);
    safe_malloc_map[(uint64_t)ptr] = request;

    return ptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void safe_free_for_scheme(void* ptr)
{
    std::map<uint64_t, size_t>::iterator it = safe_malloc_map.find((uint64_t)ptr);
    if (it == safe_malloc_map.end())
    {
        Log(PDO_LOG_ERROR, "attempt to free memory not allocated");
        return;
    }

    safe_malloc_map.erase(it);
    free(ptr);
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
    pe::ThrowIfNull(psymbol, "Unable to find/create symbol");

    pproperty = mk_symbol(sc, property);
    pe::ThrowIfNull(pproperty, "Unable to find/create property");

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
    pe::ThrowIfNull(pvalue, "Unable to create string for property");

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
    char *buffer,
    size_t bufsize
    )
{
    Zero(buffer, bufsize);
    scheme_set_output_port_string(sc, buffer, buffer + bufsize);

    pointer writesym = scheme_find_symbol(sc, "write");
    pe::ThrowIf<pe::RuntimeError>(writesym == sc->NIL, "unable to find write function symbol");

    pointer writefn = cdr(scheme_find_symbol_value(sc, sc->envir, writesym));
    pe::ThrowIf<pe::RuntimeError>(writefn == sc->NIL, "unable to find write function definition");

    scheme_call(sc, writefn, cons(sc, value, sc->NIL));
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "failed to write expression to buffer");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GipsyInterpreter::~GipsyInterpreter(void)
{
    scheme* sc = &this->interpreter;
    scheme_deinit(sc);

    size_t total = 0;

    std::map<uint64_t, size_t>::iterator it  = safe_malloc_map.begin();
    while (it != safe_malloc_map.end())
    {
        free((void*)it->first);
        total += it->second;
        it++;
    }

    // Log(PDO_LOG_INFO, "tinyscheme leaked %d", total);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GipsyInterpreter::GipsyInterpreter(void)
{
    safe_malloc_map.clear();

    /* ---------- Create the interpreter ---------- */
    scheme* sc = &this->interpreter;

    //int status = scheme_init(sc);
    int status = scheme_init_custom_alloc(sc, safe_malloc_for_scheme, safe_free_for_scheme);
    // Log(PDO_LOG_INFO, "scheme interpreter initialized with status %d, %d", status, sc->no_memory);

    pe::ThrowIf<pe::RuntimeError>(
        status == 0,
        "Failed to create the gipsy scheme interpreter");

    /* ---------- Load extensions ---------- */
    scheme_load_extensions(sc);

    /* ---------- Load the base environment ---------- */
    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

    // TODO: pull the scheme error from the result buffer

    scheme_load_string(sc, (const char *)packages_init_package_scm, packages_init_package_scm_len);
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "Failed to load the gipsy initialization package");

    scheme_load_string(sc, (const char *)packages_catch_package_scm, packages_catch_package_scm_len);
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "Failed to load the gipsy error handling package");

    scheme_load_string(sc, (const char *)packages_oops_package_scm, packages_oops_package_scm_len);
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "Failed to load the gipsy object package");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::save_dependencies(
    map<string,string>& outDependencies
    )
{
    scheme* sc = &this->interpreter;

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
    scheme* sc = &this->interpreter;

    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

    /* ---------- Load contract code ---------- */

    scheme_load_string(sc, inContractCode.Code.c_str(), inContractCode.Code.size());
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "Failed to load the contract code");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::load_message(
    const pc::ContractMessage& inMessage
    )
{
    scheme* sc = &this->interpreter;

    if (! inMessage.Message.empty())
    {
        char result[MAX_RESULT_SIZE];
        Zero(result, MAX_RESULT_SIZE);
        scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

        /* --------------- Load the message --------------- */

        // load string evals the string in a safe environment,
        // any definitions made or modified are thrown away
        scheme_safe_load_string(sc, inMessage.Message.c_str(), inMessage.Message.size());
        pe::ThrowIf<pe::RuntimeError>(
            sc->retcode != 0,
            "Failed to load the message");

        /* message must be a list with at least the method as a parameter */
        pointer mptr = sc->value;
        pe::ThrowIf<pe::ValueError>(
            mptr == sc->EOF_OBJ,
            "Incomplete message");

        pe::ThrowIf<pe::ValueError>(
            list_length(sc, mptr) < 1,
            "Badly formed message, must be a list");

        pe::ThrowIf<pe::ValueError>(
            is_symbol(car(mptr)) == 0,
            "Badly formed message, first element must be a method");

        pointer sptr = mk_symbol(sc, "_message");
        pe::ThrowIfNull(sptr, "unable to create the _message symbol");

        scheme_define(sc, sc->global_env, sptr, mptr);
    }



    /* --------------- Assign the symbol values --------------- */
    gipsy_put_property(sc, ":message", "originator", inMessage.OriginatorID.c_str());
    gipsy_put_property_p(sc, ":ledger", "dependencies", sc->NIL);
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::load_contract_state(
    const pc::ContractState& inContractState
    )
{
    scheme* sc = &this->interpreter;

    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

    if (not inContractState.State.empty())
    {
        /* ---------- Load contract state ---------- */
        scheme_load_string(sc, inContractState.State.c_str(), inContractState.State.size());
        pe::ThrowIf<pe::RuntimeError>(
            sc->retcode != 0,
            "Failed to load the contract state");

        pointer sptr = mk_symbol(sc, "_instance");
        pe::ThrowIfNull(sptr, "unable to create the _instance symbol");

        scheme_define(sc, sc->global_env, sptr, sc->value);

        /* --------------- Assign the symbol values --------------- */
        gipsy_put_property(sc, ":contract", "state", inContractState.StateHash.c_str());
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::save_contract_state(
    pc::ContractState& outContractState
    )
{
    scheme* sc = &this->interpreter;

    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

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

    char rawstate[MAX_STATE_SIZE];
    gipsy_write_to_buffer(sc, rexpr, rawstate, MAX_STATE_SIZE);

    outContractState.State = rawstate;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::create_initial_contract_state(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    pc::ContractState& outContractState
    )
{
    scheme* sc = &this->interpreter;

    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

    // the message is not currently used though we should consider
    // how it can be implemented, throug the create-object-instance fn
    // this->load_message(inMessage);

    this->load_message(inMessage);
    this->load_contract_code(inContractCode);

    gipsy_put_property(sc, ":contract", "id", ContractID.c_str());
    gipsy_put_property(sc, ":contract", "creator", CreatorID.c_str());

    pointer _class = scheme_find_symbol(sc, inContractCode.Name.c_str());
    pe::ThrowIf<pe::ValueError>(
        _class == sc->NIL,
        "malformed contract; unable to locate the contract class");

    pointer _funcsym = scheme_find_symbol(sc, "create-object-instance");
    pe::ThrowIf<pe::ValueError>(
        _funcsym == sc->NIL,
        "malformed contract; unable to locate create-object-instance function");

    pointer _function = scheme_find_symbol_value(sc, sc->envir, _funcsym);
    pointer rexpr = scheme_call(sc, cdr(_function), cons(sc, _class, sc->NIL));
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode != 0,
        "failed to create contract instance");

    scheme_define(sc, sc->global_env, mk_symbol(sc, "_instance"), rexpr);

    this->save_contract_state(outContractState);
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void GipsyInterpreter::send_message_to_contract(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    const pc::ContractState& inContractState,
    pc::ContractState& outContractState,
    std::map<std::string,std::string>& outDependencies,
    std::string& outMessageResult
    )
{
    scheme* sc = &this->interpreter;

    char result[MAX_RESULT_SIZE];
    Zero(result, MAX_RESULT_SIZE);
    scheme_set_output_port_string(sc, result, result + MAX_RESULT_SIZE);

    this->load_message(inMessage);
    this->load_contract_code(inContractCode);
    this->load_contract_state(inContractState);

    gipsy_put_property(sc, ":contract", "id", ContractID.c_str());
    gipsy_put_property(sc, ":contract", "creator", CreatorID.c_str());

    /* this might not be the most obvious way to invoke the send function
       but this method is used to ensure that the message is not evaluated
       again with the contract context active */
    pointer _message = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "_message"));
    pointer _instance = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "_instance"));
    pointer sendfn = scheme_find_symbol_value(sc, sc->envir, scheme_find_symbol(sc, "send"));

    pointer rexpr = scheme_call(sc, cdr(sendfn), cons(sc, cdr(_instance), cdr(_message)));
    pe::ThrowIf<pe::RuntimeError>(
        sc->retcode < 0,
        "method evaluation failed");

    this->save_dependencies(outDependencies);

    /* write the result into the result buffer */
    gipsy_write_to_buffer(sc, rexpr, result, MAX_RESULT_SIZE);
    outMessageResult = result;

    this->save_contract_state(outContractState);
}
