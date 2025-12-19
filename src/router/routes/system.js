'use strict';

module.exports = (app, db) => {

    /**
     * GET /v1/status/:brand
     * @summary Check system status
     * @tags system
     * V2 FIX: Remote Code Execution (RCE)
     */
    app.get('/v1/status/:brand', (req, res) => {
        // Vulnerable code was using: exec("ping " + req.params.brand)
        
        // FIX: Removed 'child_process.exec'. 
        // We now handle logic securely using JavaScript only, avoiding OS commands.
        const brand = req.params.brand;
        
        // Safe response
        res.json({
            status: "Online",
            brand_checked: brand,
            ping: "Success (Simulated safe response)"
        });
    });

    /**
     * GET /v1/test/?url=
     * @summary Test connectivity
     * @tags system
     * V5 FIX: Server-Side Request Forgery (SSRF)
     */
    app.get('/v1/test/', (req, res) => {
        const targetUrl = req.query.url;

        if (!targetUrl) {
            return res.status(400).json({ error: "URL parameter missing" });
        }

        // FIX: Implement Whitelist
        // Only allow specific, trusted domains. Block everything else.
        const allowedUrls = [
            "http://localhost:5000",
            "http://example.com"
        ];

        if (allowedUrls.includes(targetUrl)) {
            // Simulated fetch for safe URLs
            res.json({ 
                status: 200, 
                message: "Connection successful to trusted domain",
                url: targetUrl 
            });
        } else {
            // Reject malicious or internal URLs
            res.status(403).json({ 
                error: "Forbidden: Destination not allowed (SSRF Protection)" 
            });
        }
    });

};