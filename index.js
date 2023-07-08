// Les modules on est besoin : npm i express mongodb nodemon dotenv bcrypt jsonwebtoken
// Les commandes CMD : touch .env 
const express = require('express');
const app = express();
app.use(express.json());
// Pour utiliser le fichier .env
require('dotenv').config();
// .env fichier : CONNECTION_URL = "mongodb://127.0.0.1:27017",DB_NAME ,SECRET_KEY
// Pour utiliser bcrypt
const bcrypt  = require('bcrypt');
// Pour utiliser JSON Web TOken
const jwt  = require('jsonwebtoken');
//MongoDB
const Mongoclient = require('mongodb').MongoClient;
const client = new Mongoclient(process.env.CONNECTION_URL);
let db;
client.connect().then(()=>{
    console.log('Mongodb is connected');
    db = client.db(process.env.DB_NAME)
})
app.get('/',(req,res)=>{
    res.json({"message":"Hello world"})
})
// Créer une utilisateur
app.post('/register',async(req,res)=>{
    const {username,password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection('users').insertOne({"username":username,"password":hashedPassword});
    res.send(result);   
})
// Login
app.post('/login',async(req,res)=>{
    const {username,password} = req.body;
    const user = await db.collection('users').findOne({"username":username});
    if (!user){
        res.send("user not found")
    }
    const isValid = await bcrypt.compare(password,user.password );
    if (!isValid){
        res.send("Invalid data")
    }
    // Create a JWT JSON Web Token
    const token = jwt.sign({"sub":user._id,"exp":Math.floor(Date.now()/1000 + (60 * 60))},process.env.SECRET_KEY, (err, token) => {
        if(err){
        res.status(401).json({"message" : "invalid credentials"});
        }
        res.status(401).json({token});
    });
// Le middleware pour vérifier le token
function authToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    const token = bearerHeader && bearerHeader.split(' ')[1];
    if (token == null) {
        res.sendStatus(401);
    }
    req.token = token;
    next();
}
// Une route protégée
app.get('/protected', authToken, (req, res) => {
    jwt.verify(req.token, process.env.SECRET_KEY, (err, data) => {
        if (err) {
            res.sendStatus(403);
        }
        return res.status(200).json({ 'message': "Valid token" });
    });
});
});
const port = 82;
app.listen(port,()=>{
    console.log(`Server working on http://localhost:${port}`);
})