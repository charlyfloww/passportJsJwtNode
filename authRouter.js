const router = require("express").Router();
const pool = require("../db")
const bcrypt = require("bcrypt")
const jwtTokens = require("../utils/jwtManager")
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')
const cors = require('cors');
//redis + session express configurtion
const Redis = require("redis")
const session = require("express-session")
const redisStore = require("connect-redis")(session)
const redisClient = Redis.createClient({
	host: localhost,
	port: 6739
});

app.use(session({
	store: new RedisStore({client:redisClient}),
	secret: process.env.SESSION_SECRET,
	cookie: {
		secure: false,
		resave: false,
		saveUninitialized: false,
		httpOnly: true,
		maxAge: 300000
	}
}))

router.use(cookieParser());
router.use(cors());

const EXPIRATION_DEFAULT_TIME = 86400; //un giorno

//login function, get username email password and generate jwt, store it in redis with user id as a key, uuid as 
//user id in postgresql viene geenrato al register
router.post("/login", async(req, res)=>{
  try {
  	//search for teh username in the db
  	const username = req.body.username
	const user = await pool.query("SELECT * FROM authdata WHERE username=$1 ", [username])
	// no username found
	if (user.rows.length === 0) return res.status(401).send("Username or Password is incorrect!");
	//chec of the hashe passowrd is the same of the hash generated from th einput password
	const userIsAuth = await bcrypt.compare( password, user.rows[0].password)
	//se le passowrd non corrispondono
	if(!userIsAuth) return res.status(401).send("Username or Password is incorrect!");
	//generate token with the payload passed, user id and username
	const tokens = jwtTokens(user.rows[0].id, user.rows[0].username);
	//store in redis user id -> token
	redisClient.set(username.toString(), JSON.stringify({token: tokens.refreshToken}), (err, reply)=>{      
		  redisClient.get(username.toString(), (err, reply) => {
		  if (err) {
		   console.log("Unable to set the token the ref token");
		   throw err
		  }
		  const isAuthorized = true;
	     });
	    })
	//send the refresh token as a cookie 
	res.cookie("refreshToken", tokens.refreshToken, {httpOnly:true})
	const isAuthorized=true
	const User = {username:username, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, isAuthorized: isAuthorized}
	//res.json(tokens)
	res.json(User)
		}
	catch(err)
	{
		console.log(err)
		res.status(500).send("Server error..")
	}
})

router.post("/register", async (req, res) => {
	try
	{
      const {username, email, password } = req.body;
      //check if user exists
      const user = await pool.query("SELECT * FROM authdata WHERE username=$1", [username])
      if (user.rows.length !== 0) return res.status(401).json({errorMessage: "Username already in use, not registered."})//.send("User aleady exists!")
      //bcrypt password
      const saltRound = 10;
      const salt = await bcrypt.genSalt(saltRound);
      const hashedPassword = await bcrypt.hash(password, salt);
      //insert into db
      const newUser = await pool.query("INSERT INTO authdata(username,password, email) VALUES($1, $2, $3) RETURNING *",
      	[username, hashedPassword, email]);
      //generate the token -> import util function jwtToken
      const tokens = jwtTokens(newUser.rows[0].id, newUser.rows[0].username);
/*
      redisClient.set(username.toString(), JSON.stringify({token: tokens.refreshToken}), (err, reply)=>{})
      res.cookie("refreshToken", tokens.refreshToken, {httpOnly:true})
      var isAuthorized = true;
      res.json({accessToken: tokens.accessToken, refreshToken: tokens.refreshToken ,isAuthorized:isAuthorized})
      //res.status(200).send("Registered!")
*/
	} catch(err) {
      console.log(err)
      res.status(500).send("server error");
	}
})




//refresh token
router.post("/refreshtoken", async (req, res) => {
  try {
    //const refreshToken = req.cookies.refresh_token;
    const {username} = req.body 
    console.log(username)
    const {token} = await getOrSetCache(username.toString(), ()=>{
    	console.log("Unauthorizedssss")
        redisClient.get(username.toString(), (err, data)=>{
    	if(err)
    		{console.log(err)}
	        console.log(data)
	        const refreshToken = data.token
	        return refreshToken
        })
    })
    console.log(token)
    if (token === null)  {console.log("no token");return res.sendStatus(401);}
    jwt.verify(token, process.env.REFRESH_TOKEN, (error, user) => {
        if (error) return res.status(403).json({error:error.message});
	    let tokens = jwtTokens(user.id, user.username);
	    //res.cookie('refresh_token', tokens.refreshToken, {...(process.env.COOKIE_DOMAIN && {domain: process.env.COOKIE_DOMAIN}) , httpOnly: true,sameSite: 'none', secure: true});
	    res.cookie("refreshToken", tokens.refreshToken, {httpOnly:true})
	    redisClient.setex(username.toString(), EXPIRATION_DEFAULT_TIME, JSON.stringify({token: token}))
	    
	    //console.log(user)
	    return res.json(tokens);
	    //prendere l'access token e inserirlo nella req succesiva
    });
  } catch (error) {
    res.status(401).json({error: error.message});
  }
});

//delete refresh token, per esempio logout
router.post("/logout", authenticateToken, async (req, res)=>{
	try
	{
		const {username} = req.body
		const token =req.headers["authorization"].split(" ")[1]
		//delete from redis
		// remove the refresh token
	    await redisClient.del(username.toString());
	    // blacklist current access token
	    await redisClient.set('BL_' + username.toString(), token);
	    res.clearCookie("refreshToken");
	    const isAuthorized=false;
	    return res.json({status: true, message: "success.", isAuthorized:isAuthorized});
    }
    catch(err)
    {
    	const isAuthorized=false;
    	res.json({error:err, isAuthorized:isAuthorized})
    }
})

function verify(token){
	if (token === null)  {
		console.log("no token");
		return res.sendStatus(401);
	}
	jwt.verify(token, process.env.REFRESH_TOKEN, (error, user) => {
        if (error) 
        	return res.status(403).json({error:error.message});
	    let tokens = jwtTokens(user.id, user.username);
	    res.cookie("refreshToken", tokens.refreshToken, {httpOnly:true})
	    redisClient.setex(user.username.toString(), EXPIRATION_DEFAULT_TIME, JSON.stringify({token: token}))
	    //console.log(user)
	    res.json({tokens,user});
	    //prendere l'access token e inserirlo nella req succesiva
    });
}


function getOrSetCache (key, cb) { 
	return new Promise((resolve, reject)=>{
		redisClient.get(key, async (error, data)=>{ //se alla key corrispondono dei dati sono in data
		  if(error) return reject(error)
		  if(data != null) return resolve(JSON.parse(data)) //se trova dati li ritorna
		  //get new fresh data through the callback
		  const freshData = await cb()
		  redisClient.setex(key, EXPIRATION_DEFAULT_TIME, JSON.stringify(freshData))//from json format to string
		  resolve(freshData)
		})
	})
}



