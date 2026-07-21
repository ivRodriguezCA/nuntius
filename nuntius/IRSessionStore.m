/*
 The MIT License (MIT)
 Copyright © 2017 Ivan Rodriguez. All rights reserved.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import "IRSessionStore.h"

/* IRSessionStore.h is a protocol plus one small value type. This file exists for that value type
   alone; there is no default implementation of the protocol, deliberately — IRInMemorySessionStore
   and IRSealedSessionStore differ in where records live, and a shared abstract base would put the
   §11.1.1 collapse in a place neither owns. */

@interface IRSessionEstablishResult ()
- (instancetype _Nullable)initPrivate;
@end

@implementation IRSessionEstablishResult {
    IRSession *_survivingSession;
    IRSession *_tornDownSession;
    NSData *_tornDownHandshakeId;
    BOOL _incomingSessionSurvived;
}

+ (instancetype _Nullable)resultWithSurvivingSession:(IRSession * _Nonnull)survivingSession
                                     tornDownSession:(IRSession * _Nullable)tornDownSession
                             incomingSessionSurvived:(BOOL)incomingSessionSurvived {
    if (survivingSession == nil) {
        return nil;
    }

    IRSessionEstablishResult *result = [[IRSessionEstablishResult alloc] initPrivate];
    if (result == nil) {
        return nil;
    }

    result->_survivingSession = survivingSession;
    result->_tornDownSession = tornDownSession;
    result->_incomingSessionSurvived = incomingSessionSurvived;

    /* CAPTURED HERE, not read from `tornDownSession` on demand. -tearDown zeroizes the ratchet
       state, and a caller reaching through a dead object for its id is one refactor away from
       reaching for something that is gone. §11.6 needs the id to survive the session. */
    result->_tornDownHandshakeId = [tornDownSession.handshakeId copy];

    return result;
}

- (instancetype _Nullable)initPrivate {
    return [super init];
}

- (IRSession * _Nonnull)survivingSession {
    return _survivingSession;
}

- (IRSession * _Nullable)tornDownSession {
    return _tornDownSession;
}

- (BOOL)incomingSessionSurvived {
    return _incomingSessionSurvived;
}

- (NSData * _Nullable)tornDownHandshakeId {
    return _tornDownHandshakeId;
}

- (BOOL)collapseOccurred {
    return (_tornDownSession != nil);
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; incoming survived = %@; collapse = %@>",
            NSStringFromClass([self class]), (void *)self,
            (_incomingSessionSurvived ? @"YES" : @"NO"),
            (_tornDownSession != nil ? @"YES" : @"NO")];
}

@end
