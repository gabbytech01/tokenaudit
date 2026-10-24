const router = require('express').Router();
const db = require('./db');

// GET /invoice/:id
router.get('/invoice/:id', auth, async (req, res) => {
  const inv = await db.invoices.findOne({ id: req.params.id, owner: req.user.id });
  res.json(inv);
});

module.exports = router;