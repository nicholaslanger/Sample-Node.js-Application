var LocalStrategy = require('passport-local').Strategy;

// load up the user model
var User = require('../model/user');

module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id).then(function(user) {
            done(null, user);
        }).catch(function(err) {
            done(err);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, email, password, done) {
            if (email)
                email = email.toLowerCase();

            process.nextTick(function() {
                User.findOne({ 'local.email': email }).then(function(user) {
                    if (!user)
                        return done(null, false, req.flash('loginMessage', 'No user found.'));

                    if (!user.validPassword(password))
                        return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));

                    return done(null, user);
                }).catch(function(err) {
                    return done(err);
                });
            });

        }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, email, password, done) {
            if (email)
                email = email.toLowerCase();

            process.nextTick(function() {
                if (!req.user) {
                    User.findOne({ 'local.email': email }).then(function(user) {
                        if (user) {
                            return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                        }

                        var newUser = new User();
                        newUser.local.email = email;
                        newUser.local.password = newUser.generateHash(password);
                        newUser.local.first_name = req.body.first_name;
                        newUser.local.last_name = req.body.last_name;

                        return newUser.save().then(function() {
                            return done(null, newUser);
                        });
                    }).catch(function(err) {
                        return done(err);
                    });
                } else if (!req.user.local.email) {
                    User.findOne({ 'local.email': email }).then(function(user) {
                        if (user) {
                            return done(null, false, req.flash('loginMessage', 'That email is already taken.'));
                        }

                        var currentUser = req.user;
                        currentUser.local.email = email;
                        currentUser.local.password = currentUser.generateHash(password);

                        return currentUser.save().then(function() {
                            return done(null, currentUser);
                        });
                    }).catch(function(err) {
                        return done(err);
                    });
                } else {
                    return done(null, req.user);
                }
            });

        }));

};
