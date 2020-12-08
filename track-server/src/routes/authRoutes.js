const express = require('express')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const User = mongoose.model('User')
const NodeRSA = require('node-rsa');
const crypto = require('crypto')
const router = express.Router();
var key = new NodeRSA( { b: 1024 } );
const assert = require('assert');



router.post('/signup', async (req,res) => {
  const { email, password} = req.body;
  try{
    const user = new User({ email, password});
    await user.save();
    const token =jwt.sign({userId:user._id}, 'MY_SECRET_KEY');
    res.send({ token });
  }catch(err){
    return res.status(422).send(err.message)
  }

})

router.post('/signin', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(422).send({error: 'Must provide email and password'})
  }

  const user = await User.findOne({ email }); 
  if(!user) {
    return res.status(404).send({error: 'Invalid password or email'})
  }

  try{
    await user.comparePassword(password);
    const token = jwt.sign({userId: user._id},'MY_SECRET_KEY')
    res.send({ token })
  }catch(err){
    return res.status(422).send({err:'Invalid password or email'})
  }
})

router.post('/rsa', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(422).send({error: 'Must provide email and password'})
  }
  const user = await User.findOne({email});
  if(!user) {
    return res.status(404).send({error: 'Invalid password or email'})
  }
  try{
    await user.comparePassword(password);
    const token = jwt.sign({userId: user._id},'MY_SECRET_KEY')
    const ecdh = crypto.createECDH('secp521r1');
    ecdh.generateKeys();
    const compressedKey = ecdh.getPublicKey('hex', 'compressed');

    const publicKey = key.exportKey('public')
    const privateKey = key.exportKey('private')
    // const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    //   // The standard secure default length for RSA keys is 2048 bits
    //   modulusLength: 1024,
    // })
    res.send({ publicKey, privateKey })
  }catch(err){
    return res.status(422).send({err:'Invalid password or email'})
  }
})

module.exports = router;
