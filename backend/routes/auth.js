
const express = require('express');
const router = express.Router();      

const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');     
var jwt = require('jsonwebtoken');  
let fetchuser = require('../middleware/fetchuser'); 
const User = require('../models/User');

JWT_SECRET = 'Onetwothree';


router.post('/createuser',[
    body('name','Enter a valid name').isLength({min : 3}),
    body('email','Enter a valid email').isEmail(),
    body('password','Password must be at least 8 characters').isLength({min : 8}),
] , async (req, res) => {
    //express-validator code which validates the requests, catches the error and sends error
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        success = false;
      return res.status(400).json({success, errors: errors.array() });
    }
    try {
        
    
    let user = await User.findOne({email: req.body.email});
    if(user){
        success = false;
        return res.status(400).json({ success,error: "Sorry a user with this email exists"})
    }

    
    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password,salt);
    

    
    user = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: secPass,
      });
   
    const data = {
        user:{
            id:user.id
        }
    }
    
    const authToken = jwt.sign(data,JWT_SECRET);
    success = true
    
    res.json({success,authToken});

    
    } catch (error) {
        
        res.status(500).send("Interval server occured");
    }
    
});


router.post('/login',[
    body('email','Enter a valid email').isEmail(),
    body('password','Password cannot be blank').exists(),
], async(req, res) => {
    let success = false;
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const {email,password} = req.body;
    try {
        let user = await User.findOne({email});     //find email in DB via findOne mongoose model  //.findOne looks for the same email(entered by user) and returns the whole user object of that particular email
        // if !user i.e no user(email) exists ,return error
        if(!user){
            success = false;
            return res.status(400).json({success,error: "Please try to Login with correct credentials."});
        }
        // console.log(user);
        //compare password by bcrypt.compare() function //compare password entered by user with user.password(i.e already existing pwd in DB )
        const passwordCompare = await bcrypt.compare(password, user.password);
        //if pwd doesnt matches/exists return error
        if(!passwordCompare){
            success = false
            return res.status(400).json({success, error: "Please try to Login with correct credentials."});
        }
        //take user id
        const data = {
            user:{
                id:user.id
            }
        }
        //send JWT Token when login //authToken is like sessionId i.e for a particular user 
        const authToken = jwt.sign(data,JWT_SECRET);
        success = true;
        res.json({success,authToken});
    } catch (error) {
        // console.error(error.message);
        res.status(500).send("Interval server occured");
    }
})


//Route 3: Get a logged in UserDetails : POST "/api/auth/getuser" endpoint 
//call the middleware function and then the async req
router.post('/getuser', fetchuser,async(req,res) => {
    try {
        //take user id //we fetched 'userId' from authToken and initialized it to {req.user} in fetchuser() func
        let userId = req.user.id;
        //find user by its 'userid' by findById() method and fetch(select) all the data except password(-password) //findByid() will search in mongoose DB with the particular id provided and return the data for that particular user (by userid)
        const user = await User.findById(userId).select("-password");
        //send the response i.e user data
        res.send(user);
    } catch (error) {
        // console.error(error.message);
        res.status(500).send("Interval server occured");
    }
})


module.exports = router;