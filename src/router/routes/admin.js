'use strict';
const os = require('os');
const multer = require('multer');
const Hoek = require('hoek');
const libxmljs = require('libxmljs'); // Import required for XXE fix

module.exports = (app, db) => {

    // Security Middleware: Ensure user is Admin
    // Fix V2: Broken Access Control
    const ensureAdmin = (req, res, next) => {
        // 1. Check if user is logged in
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: "Unauthorized. Please log in." });
        }

        // 2. Check role in Database
        db.user.findOne({ where: { id: req.session.userId } })
            .then(user => {
                if (user && user.role === 'admin') {
                    next(); // User is Admin -> Proceed
                } else {
                    res.status(403).json({ error: "Forbidden. Admin access required." });
                }
            })
            .catch(err => {
                res.status(500).json({ error: "Internal Server Error" });
            });
    };

    /**
     * POST /v1/admin/new-beer/
     * @summary use to create a new beer in the system
     * @tags admin
     */
    // Apply ensureAdmin middleware here
    app.post('/v1/admin/new-beer/', ensureAdmin, (req, res) => {

        const beerName = req.body.name;
        const beerPrice = req.body.price;
        const beerPic = req.body.picture;
        const beerCurrncy = 'USD';
        const beerStock = 'plenty';

        db.beer.create({
            name: beerName,
            currency: beerCurrncy,
            stock: beerStock,
            price: beerPrice,
            picture: beerPic,
        }).then(new_beer => {
            res.json(new_beer);
        }).catch(err => {
            res.status(500).json({ error: "Database error" });
        });
    });

    /**
     * POST /v1/admin/upload-pic/
     * @summary Image upload for admins
     * @tags admin
     */
    const uploadImage = multer({ dest: './uploads/' });
    
    // Apply ensureAdmin middleware here too
    app.post('/v1/admin/upload-pic/', ensureAdmin, uploadImage.single('file'), async function (req, res) {
        if (!req.file) {
            res.sendStatus(400);
            return;
        }

        try {
            const image = req.file;
            res.json(image);
        } catch (err) {
            res.json({ error: err.toString() });
        }
    });

    /**
     * POST /v1/admin/new-beer-xml/
     * @summary use to create a new beer using xml parsing
     * @tags admin
     */
    const storage = multer.memoryStorage();
    const upload = multer({ storage: storage });

    // Apply ensureAdmin middleware here too
    app.post('/v1/admin/new-beer-xml/', ensureAdmin, upload.single('file'), async function (req, res) {
        if (!req.file) {
            res.sendStatus(400);
            return;
        }

        try {
            const xml = req.file.buffer;
            
            // Fix V3: XXE Injection
            // Changed {noent: true} to {noent: false} to prevent Entity Expansion
            const doc = libxmljs.parseXml(xml, { noent: false });

            const beerName = doc.get('//name')?.text();
            const beerPrice = doc.get('//price')?.text();

            if (!beerName || !beerPrice) {
                 return res.status(400).json({error: "Invalid XML format"});
            }

            const beerCurrncy = 'USD';
            const beerStock = 'plenty';

            db.beer.create({
                name: beerName,
                currency: beerCurrncy,
                stock: beerStock,
                price: beerPrice,
                // picture: ... (XML parsing logic needed if picture is sent)
            }).then(new_beer => {
                res.json(new_beer);
            });

        } catch (err) {
            res.status(500).send("XML Parsing Error: " + err.toString());
        }
    });
};