require('dotenv').config();
const express = require('express');
const cors = require('cors');
const licenseRoutes = require('./license');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'rafix-license-server-simple' });
});

app.use('/api/license', licenseRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
