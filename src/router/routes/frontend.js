'use strict';

module.exports = (app, db) => {

    // Helper: Check if user is authenticated
    const isAuthenticated = (req, res, next) => {
        if (req.session && req.session.logged) {
            return true;
        }
        return false;
    };

    // Helper: Validate Message Content (Allow only letters, numbers, spaces, and basic punctuation)
    // Fix V1: Input Validation (Defense in Depth)
    const sanitizeMessage = (msg) => {
        if (!msg) return "Please log in to continue";
        
        // Regex: Allow a-z, A-Z, 0-9, space, and chars: . , ! ? ' -
        // Reject everything else (like < > { } / \ etc.)
        const safePattern = /^[a-zA-Z0-9\s.,!?'-]+$/;
        
        if (safePattern.test(msg)) {
            return msg;
        } else {
            // If malicious chars detected, return generic error
            return "Invalid characters detected in message!";
        }
    };

    //Front End entry page
    app.get('/', (req, res) => {
        // Fix V1: Input Validation + Sanitization
        const rawMessage = req.query.message;
        const safeMessage = sanitizeMessage(rawMessage);

        res.render('user.html', {
            message: safeMessage
        });
    });

    //Front End register page
    app.get('/register', (req, res) => {
        // Fix V1: Input Validation + Sanitization
        const rawMessage = req.query.message;
        const safeMessage = sanitizeMessage(rawMessage);

        res.render('user-register.html', {
            message: safeMessage
        });
    });

    //Front End route to Register
    app.get('/registerform', (req, res) => {
        const userEmail = req.query.email;
        const userName = req.query.name;
        const userRole = 'user';
        const userPassword = req.query.password;
        const userAddress = req.query.address;

        // FIX: Check if fields are undefined BEFORE processing
        if (!userEmail || !userPassword || !userName) {
             return res.redirect("/register?message=All fields are required.");
        }

        //validate email using regular expression
        var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
        
        if (!emailExpression.test(userEmail)) {
            res.redirect("/register?message=Email couldn't be validated, please try again.");
            return;
        }

        const md5 = require('md5');
        db.user.create({
            name: userName,
            email: userEmail,
            role: userRole,
            address: userAddress,
            password: md5(userPassword)
        }).then(new_user => {
            req.session.logged = true;
            req.session.userId = new_user.id; 
            res.redirect('/profile?id=' + new_user.id);
        }).catch((e) => {
            console.log(e);
            res.redirect('/?message=Error registering, please try again');
        });
    });

    //Front End route to log in
    app.get('/login', (req, res) => {
        var userEmail = req.query.email;
        var userPassword = req.query.password;
        
        // FIX CRASH: Handle missing input
        if (!userEmail || !userPassword) {
            return res.redirect('/?message=Please enter both email and password');
        }

        db.user.findAll({
            where: {
                email: userEmail
            }
        }).then(user => {
            if (user.length == 0) {
                res.redirect('/?message=Password was not found! Please Try again');
                return;
            }

            const md5 = require('md5');
            //compare password
            if ((user[0].password == userPassword) || (md5(user[0].password) == userPassword)) {
                req.session.logged = true;
                req.session.userId = user[0].id; // IDOR Protection
                res.redirect('/profile?id=' + user[0].id);
                return;
            }
            res.redirect('/?message=Password was not correct, please try again');
        });
    });

    //Front End route to profile
    app.get('/profile', (req, res) => {

        if (!req.query.id) {
            res.redirect("/?message=Could not Access profile please log in or register");
            return;
        }

        // Fix V10: IDOR Protection
        if (!req.session.logged) {
             return res.redirect('/?message=Please log in first');
        }

        if (req.session.userId != req.query.id) {
            return res.status(403).send("Forbidden: You cannot view other users' profiles (IDOR Protection).");
        }

        db.user.findAll({
            include: 'beers', 
            where: {
                id: req.query.id
            }
        }).then(user => {
            if (user.length == 0) {
                res.redirect('/?message=User not found, please log in');
                return;
            }
            
            db.beer.findAll().then(beers => {
                res.render('profile.html', {
                    beers: beers,
                    user: user[0]
                });
            });
        });
    });

    //Front End route to beer
    app.get('/beer', (req, res) => {

        if (!req.query.id) {
            res.redirect("/?message=Could not Access beer please try a different beer");
            return;
        }

        // Fix IDOR in Beer Route
        if (req.query.user && req.session.userId != req.query.user) {
             return res.status(403).send("Forbidden: IDOR detected.");
        }

        db.beer.findAll({
            include: 'users',
            where: {
                id: req.query.id
            }
        }).then(beer => {
            if (beer.length == 0) {
                res.redirect('/?message=Beer not found, please try again');
                return;
            }
            
            db.user.findOne({
                where: {
                    id: req.query.user
                }
            }).then(user => {
                if (!user) {
                    res.redirect('/?message=User not found, please try again');
                    return;
                }
                user.hasBeer(beer).then(result => {
                    let love_message;
                    if (result) { 
                        love_message = "You Love THIS BEER!!";
                    } else { 
                        love_message = "...";
                    }
                    
                    if (req.query.relationship) {
                        // Sanitize relationship message too!
                        love_message = sanitizeMessage(req.query.relationship);
                    }

                    res.render('beer.html', {
                        beers: beer,
                        message: love_message,
                        user: user
                    });

                });
            });
        });
    });
};