/**
 * Created by dsandor on 11/22/14.
 */

var sessionTokens = require('../lib/index.js')();
var sessionResponse;

describe('test the session-tokens functions', function() {

    it('should get a session token', function (done) {
        sessionTokens.createSession(function (response) {
            expect(response).not.toBe(null);
            expect(response.sessionToken).not.toBe(null);

            sessionResponse = response;
        },
        function(error) {
            console.log('An error occurred while creating session: %j', error);

            it('should not produce an error', function(){
                expect(true).toBe(false);
            });
        });
        done();
    });

    it('should validate ok with a good session token', function(done) {

        sessionTokens.validateSession(sessionResponse.sessionToken, sessionResponse.nonce,
        function(response) {
            expect(response).not.toBe(null);
            expect(response.newSessionInformation).not.toBe(null);
            expect(response.newSessionInformation.sessionToken).toBe(sessionResponse.sessionToken);
        },
        done
        );
        done();
    });

    it('should validate unsuccessfully with a bad session token', function(done) {
        sessionTokens.validateSession('bad_token', sessionResponse.nonce,
            function(response) {
                expect(response).not.toBe(null);
                expect(response.newSessionInformation).toBe(null);
                expect(response.success).toBe(false);
            },
            function(err) {
                done();
            }
        );
        done();
    });

    it('should destroy session', function(done) {
        sessionTokens.destroySession(sessionResponse.sessionToken,
            function() {
                done();
            },
            function(err) {
                done('failed destroying session: ' + err.message);
            });
    });

    it('should not have a session after its destroyed', function(done) {
        sessionTokens.validateSession(sessionResponse.sessionToken, sessionResponse.nonce,
            function(response) {
                done('failed because a session still existed after being destroyed');
            },
            function(err)
            {
                done();
            }
        );
    });
});
