'use strict';
var fs = require('fs');
var path = require('path'); // Important for Path Traversal fix

module.exports = (app, db) => {
    //https://github.com/BRIKEV/express-jsdoc-swagger
    
    /**
     * GET /v1/order
     * @summary Use to list all available beer
     * @tags beer
     * @return {array<Beer>} 200 - success response - application/json
     */
    app.get('/v1/order', (req, res) => {
        // Fix Excessive Data Exposure: Removed {include: "users"} to prevent leaking user PII
        db.beer.findAll({
            attributes: ['id', 'name', 'price', 'currency', 'stock', 'picture'] // Select only safe fields
        })
        .then(beer => {
            res.json(beer);
        })
        .catch(err => {
            res.status(500).send("Database Error");
        });
    });

    /**
     * GET /v1/beer-pic/
     * @summary Get a picture of a beer
     * @param {string} picture.query.required picture identifier
     * @tags beer
     */
    app.get('/v1/beer-pic/', (req, res) => {
        if (!req.query.picture) {
            return res.status(400).send("Picture parameter is required");
        }

        // Fix V6 Path Traversal: Use path.basename to strip directory traversal characters (../)
        var filename = path.basename(req.query.picture); 
        var filePath = path.join(__dirname, '../../../uploads', filename);

        fs.readFile(filePath, function(err, data) {
            if (err) {
                // Don't send exact error details in production
                res.status(404).send("Image not found");
            } else {
                // Basic MIME type handling
                if (filename.endsWith('.jpg') || filename.endsWith('.jpeg')) {
                    res.type('image/jpeg');
                } else if (filename.endsWith('.png')) {
                    res.type('image/png');
                }
                
                res.send(data);
            }
        });
    });

    /**
     * GET /v1/search/{filter}/{query}
     * @summary Search for a specific beer
     * @tags beer
     * @param {string} query.path - the query to search for
     * @param {string} filter.path - the column
     * @return {array<Beer>} 200 - success response - application/json
     */
    app.get('/v1/search/:filter/:query', (req, res) => {
        const filter = req.params.filter;
        const query = req.params.query;

        // Fix V4 SQL Injection Part 1: Whitelist allowed columns
        const allowedFilters = ['name', 'price', 'id', 'stock', 'currency'];
        if (!allowedFilters.includes(filter)) {
            return res.status(400).send("Invalid filter column");
        }

        // Fix V4 SQL Injection Part 2: Use Parameterized Queries (?)
        const sql = `SELECT * FROM beers WHERE ${filter} = ?`;

        db.sequelize.query(sql, {
            replacements: [query], // Safe injection
            type: 'RAW'
        }).then(beers => {
            // Flatten the result if necessary (Sequelize raw query returns [results, metadata])
            // In 'RAW' type with replacements, it usually returns the array directly.
            const results = Array.isArray(beers) && beers.length > 0 && Array.isArray(beers[0]) ? beers[0] : beers;
            res.status(200).send(results);
        }).catch(function (err) {
            console.error(err);
            res.status(500).send("Database Error");
        });
    });
};