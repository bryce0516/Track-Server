require('./models/User')
require('./models/Track')
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes')
const trackRoutes = require('./routes/trackRoutes')
const requireAuth = require('./middleware/requireAuth')

const app = express();

app.use(bodyParser.json())
app.use(authRoutes)
app.use(trackRoutes)

const mongoUri = 'mongodb+srv://nelv13:p074425*@cluster0.wrrqa.mongodb.net/test?retryWrites=true&w=majority'

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useCreateIndex:true,
  useUnifiedTopology: true
});

mongoose.connection.on('connected', () => {
  console.log('connected to mongo instance')
});

mongoose.connection.on('error', (err) => {
  console.error('Error connecting to mongo', err)
})

app.get('/', requireAuth ,(req,res) => {
  res.send(`your email: ${req.user.email}`);
})

app.listen(3003, () => {
  console.log('listening on port 3003')
})