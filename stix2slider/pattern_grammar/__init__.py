'''
Validates a user entered pattern against STIXPattern grammar.
'''

from __future__ import print_function

import six

from antlr4 import CommonTokenStream, InputStream
from stix2patterns.grammars.STIXPatternLexer import STIXPatternLexer
from stix2patterns.grammars.STIXPatternParser import STIXPatternParser
from stix2patterns.validator import STIXPatternErrorListener
from .STIXPatternVisitor import STIXPatternVisitorForSlider


def create_pattern_object(pattern):
    '''
    Validates a pattern against the STIX Pattern grammar.  Error messages are
    returned in a list.  The test passed if the returned list is empty.
    '''

    start = ''
    if isinstance(pattern, six.string_types):
        start = pattern[:2]
        pattern = InputStream(pattern)

    if not start:
        start = pattern.readline()[:2]
        pattern.seek(0)

    parseErrListener = STIXPatternErrorListener()

    lexer = STIXPatternLexer(pattern)
    # it always adds a console listener by default... remove it.
    lexer.removeErrorListeners()

    stream = CommonTokenStream(lexer)

    parser = STIXPatternParser(stream)
    parser.buildParseTrees = True
    # it always adds a console listener by default... remove it.
    parser.removeErrorListeners()
    parser.addErrorListener(parseErrListener)

    # To improve error messages, replace "<INVALID>" in the literal
    # names with symbolic names.  This is a hack, but seemed like
    # the simplest workaround.
    for i, lit_name in enumerate(parser.literalNames):
        if lit_name == u"<INVALID>":
            parser.literalNames[i] = parser.symbolicNames[i]

    tree = parser.pattern()
    builder = STIXPatternVisitorForSlider()
    return builder.visit(tree)
