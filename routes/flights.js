const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const Flight = require('../models/Flight'); 
const router = express.Router();
const { verifyToken } = require('../middleware/auth');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, try again later.'
});
router.get('/', async (req, res) => {
    try {
        const { from, to } = req.query;
        const filter = {};
        if (from) filter.from = from;
        if (to) filter.to = to;
        const flights = await Flight.find(filter);
        res.json(flights.map(f => ({ ...f._doc, id: f._id })));
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch flights'
        });
    }
});

router.get('/:id', verifyToken, async (req, res) => {
    try {
        const f = await Flight.findById(req.params.id);
        f ? res.json({ ...f._doc, id: f._id }) :
        res.status(404).json({ error: 'Flight not found' });
    } catch {
        res.status(400).json({ error: 'Invalid ID' });
    }
});
router.post('/', async (req, res) => {
    try {
        const newFlight = new Flight(req.body);
        const saved = await newFlight.save();
        res.status(201).json({ ...saved._doc, id: saved._id });
    } catch {
        res.status(400).json({ error: 'Invalid input' });
    }
});

router.delete('/:id', async (req, res) => {
    try {
        const deleted = await Flight.findByIdAndDelete(req.params.id);
        deleted ? res.json({ message: 'Flight deleted' }) :
        res.status(404).json({ error: 'Not found' });
    } catch {
        res.status(400).json({ error: 'Invalid ID' });
    }
});

module.exports = router;