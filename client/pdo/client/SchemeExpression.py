# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from pyparsing import Forward, Group, Literal, OneOrMore, Or, Word, ZeroOrMore, Keyword
from pyparsing import alphanums, nums, dblQuotedString, QuotedString
from pyparsing import ParseResults

logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class SchemeExpression(object) :
    """
    The SchemeExpression class is used to simplify conversion to and
    from Scheme s-expressions. The class provides functions for creating
    well-formed expressions from python data types and for parsing
    s-expressions into python data structures.

    TODO: vectors, quotes, backquotes and commas are not supported at present
    """

    # -----------------------------------------------------------------
    @classmethod
    def make_expression(cls, expr) :
        """Convert a python expression into an SchemeExpression
        """
        if isinstance(expr, SchemeExpression) :
            return expr

        if type(expr) is dict :
            result = []
            for k, v in expr.items() :
                result.append([cls.make_expression(k).expression, cls.make_expression(v).expression])
            return cls.make_list(result)
        if type(expr) is list :
            result = []
            for e in expr :
                result.append(cls.make_expression(e).expression)
            return cls.make_list(result)
        elif type(expr) is tuple :
            result = []
            for e in expr :
                result.append(cls.make_expression(e).expression)
            return cls.make_vector(result)
        elif type(expr) is str :
            return cls.make_string(expr)
        elif type(expr) is int :
            return cls.make_integer(expr)
        elif type(expr) is float :
            return cls.make_float(expr)
        elif type(expr) is bool :
            return cls.make_boolean(expr)

        raise ValueError('unrecognized expression', str(expr))

    # -----------------------------------------------------------------
    @classmethod
    def make_list(cls, exprlist) :
        result = []
        for expr in exprlist :
            if not isinstance(expr, SchemeExpression) :
                expr = SchemeExpression(expr)

            result.append(expr.expression)

        return cls(result)

    # -----------------------------------------------------------------
    @classmethod
    def make_vector(cls, exprlist) :
        result = []
        for expr in exprlist :
            if not isinstance(expr, SchemeExpression) :
                expr = SchemeExpression(expr)

            result.append(expr.expression)

        return cls({ 'type' : 'vector', 'value' : result})

    # -----------------------------------------------------------------
    @classmethod
    def make_string(cls, value) :
        # if the string is delimited by quotes then strip them first, if
        # you really want double quotes then escape them
        value = str(value)
        if value.startswith('"') :
            assert value.endswith('"')
            value = value[1:-1]

        value = value.encode('utf-8').decode('unicode-escape').replace('\\"','"')
        return cls({ 'type' : 'string', 'value' : str(value) })

    # -----------------------------------------------------------------
    @classmethod
    def make_symbol(cls, value) :
        return cls({ 'type' : 'symbol', 'value' : str(value) })

    # -----------------------------------------------------------------
    @classmethod
    def make_integer(cls, value) :
        return cls({ 'type' : 'integer', 'value' : int(value) })

    # -----------------------------------------------------------------
    @classmethod
    def make_boolean(cls, value) :
        return cls({ 'type' : 'boolean', 'value' : bool(value) })

    # -----------------------------------------------------------------
    @classmethod
    def cons(cls, expr1, expr2) :
        if not expr2.islist() :
            raise ValueError('cons parameter must be a list', str(expr2))

        expr = [expr1.expression] + expr2.expression[:]
        return cls(expr)

    # -----------------------------------------------------------------
    @classmethod
    def append(cls, *exprlist) :
        result = []
        for expr in exprlist :
            if not isinstance(expr, SchemeExpression) :
                raise ValueError('append parameter must be a scheme expression', str(expr))

            if not expr.islist() :
                raise ValueError('append parameter must be a list', str(expr))

            result.extend(expr.expression[:])

        return cls(result)

    # -----------------------------------------------------------------
    @staticmethod
    def eqv(expr1, expr2) :
        if expr1.islist() and expr2.islist() :
            if expr1.length() != expr2.length() :
                return False
            for i in range(0, expr1.length()) :
                if not SchemeExpression.eqv(expr1.nth(i), expr2.nth(i)) :
                    return False
            return True

        if expr1.type == expr2.type :
            return expr1.value == expr2.value

        return False

    # -----------------------------------------------------------------
    @staticmethod
    def _tostring(expr) :
        if isinstance(expr, list) :
            result = []
            for item in expr :
                result.append(SchemeExpression._tostring(item))
            return "(" + " ".join(result) + ")"
        elif isinstance(expr, dict) :
            etype = expr['type']
            if etype == 'symbol' :
                return expr['value']
            elif etype == 'integer' :
                return str(expr['value'])
            elif etype == 'string' :
                return '"' + expr['value'].encode('unicode-escape').decode().replace('"', '\\"') + '"'
            elif etype == 'boolean' :
                return "#t" if expr['value'] else "#f"
            elif etype == 'vector' :
                result = []
                for item in expr['value'] :
                    result.append(SchemeExpression._tostring(item))
                return "#(" + " ".join(result) + ")"
            else :
                raise ValueError('unknown expression type', etype)

        raise ValueError('unexpected expression', str(expr))

    # -----------------------------------------------------------------
    @staticmethod
    def _tovalue(expr) :
        if isinstance(expr, list) :
            result = []
            for item in expr :
                result.append(SchemeExpression._tovalue(item))
            return result
        elif isinstance(expr, dict) :
            etype = expr['type']
            if etype == 'vector' :
                result = []
                for item in expr['value'] :
                    result.append(SchemeExpression._tovalue(item))
                return tuple(result)
            else :
                return expr['value']

        raise ValueError('unexpected expression', str(expr))

    # -----------------------------------------------------------------
    @staticmethod
    def _flatten(expr) :
        if isinstance(expr, ParseResults) :
            result = []
            items = list(expr)
            for item in items :
                result.append(SchemeExpression._flatten(item))
            return result

        return expr

    # -----------------------------------------------------------------
    @classmethod
    def ParseExpression(cls, source) :
        # atoms
        boolean = Keyword('#f') | Keyword('#t')
        boolean.setParseAction(lambda s, l, t : SchemeExpression.make_boolean(t[0] == '#t').expression)

        symbol = Word(alphanums + '-_')
        symbol.setParseAction(lambda s, l, t : SchemeExpression.make_symbol(t[0]).expression)

        integer = Word(nums)
        integer.setParseAction(lambda s, l, t: SchemeExpression.make_integer(t[0]).expression)

        string = QuotedString('"', multiline=True)
        string.setParseAction(lambda s, l, t: SchemeExpression.make_string(t[0]).expression)

        element = integer | boolean | symbol | string

        # lists
        lexpr = Forward()
        vexpr = Forward()

        lparen = Literal('(').suppress()
        rparen = Literal(')').suppress()
        hashsym = Literal('#').suppress()

        # vectors
        lexpr << Group(lparen + ZeroOrMore(element ^ lexpr ^ vexpr) + rparen)
        lexpr.setParseAction(lambda s, l, t: SchemeExpression.make_list(t[0]))

        vexpr << Group(hashsym + lparen + ZeroOrMore(element ^ lexpr ^ vexpr) + rparen)
        vexpr.setParseAction(lambda s, l, t: SchemeExpression.make_vector(t[0]))

        # final...
        sexpr = element | vexpr | lexpr

        sexpr.keepTabs = True             # this seems to be necessary to fix a problem with pyparsing
        result = sexpr.parseString(source)[0]
        return cls(SchemeExpression._flatten(result))

    # -----------------------------------------------------------------
    def __init__(self, expr) :
        if isinstance(expr, SchemeExpression) :
            self._expression = expr.expression
        else :
            self._expression = expr

    # -----------------------------------------------------------------
    def __str__(self) :
        return SchemeExpression._tostring(self._expression)

    @property
    def value(self) :
        return self._tovalue(self._expression)

    # -----------------------------------------------------------------
    @property
    def expression(self) :
        return self._expression

    # -----------------------------------------------------------------
    @property
    def type(self) :
        if isinstance(self._expression, list) :
            return 'list'

        return self._expression['type']

    # -----------------------------------------------------------------
    def islist(self) :
        return isinstance(self._expression, list)

    # -----------------------------------------------------------------
    def isnull(self) :
        return isinstance(self._expression, list) and len(self._expression) == 0

    # -----------------------------------------------------------------
    def length(self) :
        if self.islist() :
            return len(self._expression)
        raise ValueError('expression must be a list')

    # -----------------------------------------------------------------
    def car(self) :
        if not isinstance(self._expression, list) :
            raise ValueError('expression must be a list')

        return SchemeExpression(self._expression[0])

    # -----------------------------------------------------------------
    def cdr(self) :
        if not isinstance(self._expression, list) :
            raise ValueError('expression must be a list')

        return SchemeExpression(self._expression[1:])

    # -----------------------------------------------------------------
    def nth(self, index) :
        if not isinstance(self._expression, list) :
            raise ValueError('expression must be a list')

        if index < 0 or len(self._expression) <= index :
            raise IndexError('invalid index')

        return SchemeExpression(self._expression[index])

    # -----------------------------------------------------------------
    def assoc(self, expr) :
        if not isinstance(self._expression, list) :
            raise ValueError('source must be a list')

        for i in range(0, len(self._expression)) :
            pair = self.nth(i)
            if not pair.islist() :
                raise ValueError('source must be a list of pairs')
            head = pair.car()
            if (SchemeExpression.eqv(head, expr)) :
                return pair

        return SchemeExpression([])

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
if __name__ == '__main__' :
    print(str(SchemeExpression.ParseExpression('1')))
    print(str(SchemeExpression.ParseExpression('"string"')))
    print(str(SchemeExpression.ParseExpression('symbol')))
    print(str(SchemeExpression.ParseExpression('#f')))
    print(str(SchemeExpression.ParseExpression('#(1 "a" b)')))
    print(str(SchemeExpression.ParseExpression('(1 "a" b)')))

    source = '((make-instance escrow-counter (key "auction") (value 5) (owner "5Jd0NZuH")) #(1 2 #(3 3 3) 4) "BPdk1kJj")'
    print(str(SchemeExpression.ParseExpression(source)))

    e1 = SchemeExpression.ParseExpression('(1 2 3)')
    e2 = SchemeExpression.ParseExpression('4')
    e3 = SchemeExpression.cons(SchemeExpression.make_symbol("sym1"), e1)
    print(str(e3))
    print(str(SchemeExpression.append(e1, e3)))
    x1 = SchemeExpression.make_integer(1)
    x2 = SchemeExpression.make_symbol("sym")
    x3 = SchemeExpression.make_string("string")
    x4 = SchemeExpression.make_boolean(True)
    print(str(SchemeExpression.make_list([e1, x1, x2, x3, x4])))
