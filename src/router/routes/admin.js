'use strict';
const os = require('os');
const multer = require('multer');
const Hoek = require('hoek');
const libxmljs = require('libxmljs');

module.exports = (app, db) => {

    // Security Middleware: Ensure user is Admin
    // Fix V2 & V3: Broken Access Control
    const ensureAdmin = (req, res, next) => {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: "Unauthorized. Please log in." });
        }

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
     * @summary Image upload for admins (Secured: Admin Check + File Type Validation)
     * @tags admin
     */
    
    // Fix V7: File Upload Verification
    // Configure Multer with File Filter and Limits
    const uploadImage = multer({ 
        dest: './uploads/',
        limits: { fileSize: 2 * 1024 * 1024 }, // Limit size to 2MB
        fileFilter: (req, file, cb) => {
            // Allowed MIME types whitelist
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            
            if (allowedTypes.includes(file.mimetype)) {
                // Accept file
                cb(null, true);
            } else {
                // Reject file
                cb(new Error('Invalid file type. Only images (JPEG, PNG, GIF) are allowed.'));
            }
        }
    });
    
    // Apply ensureAdmin middleware AND the secure upload config
    app.post('/v1/admin/upload-pic/', ensureAdmin, (req, res) => {
        const upload = uploadImage.single('file');

        upload(req, res, function (err) {
            if (err) {
                // This catches the "Invalid file type" or size limit errors
                return res.status(400).json({ error: err.message });
            }

            if (!req.file) {
                return res.status(400).json({ error: "No file uploaded" });
            }

            try {
                const image = req.file;
                res.json(image);
            } catch (err) {
                res.json({ error: err.toString() });
            }
        });
    });

    /**
     * POST /v1/admin/new-beer-xml/
     * @summary use to create a new beer using xml parsing
     * @tags admin
     */
    const storage = multer.memoryStorage();
    const upload = multer({ storage: storage });

    app.post('/v1/admin/new-beer-xml/', ensureAdmin, upload.single('file'), async function (req, res) {
        if (!req.file) {
            res.sendStatus(400);
            return;
        }

        try {
            const xml = req.file.buffer;
            
            // Fix V3: XXE Injection
            // Changed {noent: true} to {noent: false}
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
            }).then(new_beer => {
                res.json(new_beer);
            });

        } catch (err) {
            res.status(500).send("XML Parsing Error: " + err.toString());
        }
    });
};