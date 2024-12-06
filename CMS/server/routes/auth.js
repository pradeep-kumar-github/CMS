const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt = require(`jsonwebtoken`)

const User = require("../models/User");

router.post("/login");

//user register route
router.post("/register", async (req, res) => {
    const { name, email, password} = req.body;

    //check all the missig fields
    if(!name || !email || !password) {
        return res
        .status(400)
        .json({error: 'Please enter all the required fields.'});
    }

    //name validation
    if(name.length > 25) {
        return res
        .status(400)
        .json({error: "name can only be less than 25 characters"});
    }

    //email validation
    const emailReg = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    
    if(!emailReg.test(email)) {
        return res
        .status(400)
        .json({error: "please enter valid email address"});
    }

    //password validation
    if(password.length < 6) {
        return res
        .status(400)
        .json({error: "password must be atleast 6 characters long"});
    }

    try {
        const doesUserAlreadyExist = await User.findOne({email});
        if(doesUserAlreadyExist) {
            return res
            .status(400)
            .json({error: `a user with the email [${email}] already exists so please try another email`});
        }

        //model creation
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({name, email, password: hashedPassword});

        //save the user
        const result = await newUser.save();
        //to make password safe
        result._doc.password = undefined;
        return res.status(201).json({...result._doc});
    } catch (err) {
        console.log(err);
        return res.status(500).json({error: err.message});
    }
})

//user login route
router.post("/login", async (req, res) => {
    const {email, password} = req.body;

    //check all the missig fields
    if(!email || !password) {
        return res
        .status(400)
        .json({error: 'Please enter all the required fields!'});
    }

    //email validation
    const emailReg = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    
    if(!emailReg.test(email)) {
        return res
        .status(400)
        .json({error: "please enter valid email address"});
    }

    try {
        const doesUserExists = await User.findOne({email});
        //if user doesnot exist
        if(!doesUserExists) {
            return res
            .status(400)
            .json({error: "Invalid email or password!"});
        }
        //if user exist
        const doesPasswordMatch = await bcrypt.compare(
            password,
            doesUserExists.password
        );

        if(!doesPasswordMatch) {
            return res
            .status(400)
            .json({error: "Invalid email or password!"});
        }

        //if all checks are passed -> generate tokens
        const payload = {_id: doesUserExists._id};
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: "1h",
        });

        return res.status(200).json({token});       
    } catch (err) {
        console.log(err);
        return res.status(500).json({error: err.message});
    }
})

module.exports = router;