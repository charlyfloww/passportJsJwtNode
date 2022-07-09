const jwt = require('jsonwebtoken');
require("dotenv").config()
//Generate an access token and a refresh token for this database user, inserting in the payload the args passed 
//to the func
function jwtTokens( id1, username1 ) {
  const user =  {id:id1, username: username1}; 
  const accessToken = jwt.sign({id:id1, username: username1}, process.env.ACCESS_TOKEN, { expiresIn: '15m' });
  const refreshToken = jwt.sign({id:id1, username: username1}, process.env.REFRESH_TOKEN, { expiresIn: '7d' });
  return ({ accessToken, refreshToken });
}

module.exports = jwtTokens;