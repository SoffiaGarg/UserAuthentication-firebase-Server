var jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
// The Cloud Functions for Firebase SDK to create Cloud Functions and setup triggers.
const functions = require('firebase-functions');

// The Firebase Admin SDK to access the Firebase Realtime Database.
const admin = require('firebase-admin');
admin.initializeApp({
    credential: admin.credential.applicationDefault()
});


let db = admin.firestore();



/**
 * ...............................................................................
 * User Login
 * .................................................................................
 * File System-
 * Right now we are not connecting with database , so saving the data in the user-db.js.
 * 
 *  - if email is present in db , if no then send error message to user "Please signUp with this email".
 *  - if email valid but password is incorrect , send the error message with status 400.
 *  - if email and password is correct , then create a access token for future authrization
 */
exports.login = functions.https.onRequest(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET');
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    try {
        let userDetail = await validateEmail(req.body.email);
        console.log("result====", userDetail);
        if (!userDetail) {
            return res.send({
                status: 401,
                message: "Email not found , please sign up first"
            })
        } else {
            if (userDetail.password === req.body.password) {
                let token = jwt.sign({
                    exp: Math.floor(Date.now() / 1000) + (60 * 60), //expire after 1 hour
                    data: req.body.email
                }, 'nodeReactApp');
                await updateAccessToken(userDetail.id, token);
                return res.send({
                    status: 200,
                    message: "Login Successfull",
                    data: {
                        token
                    }
                })
            } else {
                return res.send({
                    status: 400,
                    message: "Password is Incorrect"
                })
            }
        }
    } catch (error) {
        res.send({
            status: 400,
            message: "server error occur"
        })
    }
})


/**
 *---------------------------------------------------------------------------------
 Register User
 ..................................................................................
 * @param {} payload 

  - if email already exists send error.
  - otherwise registered user successfully.
 */
exports.register = functions.https.onRequest(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET');
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    try {
        if(req.body.email){
            let userDetail = await validateEmail(req.body.email);
            let payload = {
                ...req.body,
                token: " "
            };
            if (userDetail) {
                return res.send({
                    status: 400,
                    message: "Email Already Exists."
                })
            } else {
                let id = 'user-' + uuidv4();
                await db.collection('userAuth').doc(id).set(payload);
                return res.send({
                    status: 200,
                    message: "User Registered Successfully"
                })
            }
        }else{
            res.send({
                status:200,
                message:"Email is missing"
            })
        }
        
    } catch (error) {
        console.log("Error in Registering User",error)
    }
})


/**
 * check whether the token is valid or not.
 */
exports.verifyToken = functions.https.onRequest(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET');
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    try {
        let token = req.headers.authorization;
        console.log("token==",token);
        if (token) {
            let isVerified = await verifyAccessToken(token);
            if (isVerified) {
                return res.send({
                    status: 200,
                    message: "Access Token Verified"
                })
            } else {
                res.send({
                    status: 400,
                    message: "Token Expired"
                })
            }
        }else{
            res.send({
                status: 400,
                message: "Token Missing"
            }) 
        }
    } catch (error) {
        console.log("probelm in verifying Token")
    }
})


/**
 * -----------------------------------------------------------------------
 * Get User
 * .........................................................................
 * 
 * From access token , find the user data;
 * @param {} token 
 */
exports.getUser = functions.https.onRequest(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET');
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    try {
        let token = req.headers.authorization;
        let isVerified = await verifyAccessToken(token);
        if (!isVerified) {
            console.log("coming")
            return res.send({
                status: 400,
                message: "Access Token Expired"
            })
        } else {
            let userData = [];
            let result = await db.collection('userAuth').where('token', "==", token).get();
            if (result.empty) {
                console.log('No Matching Documents');
                return;
            } else {
                result.forEach((doc) => {
                    console.log(doc.id, '=>', doc.data());
                    let data = doc.data();
                    console.log("data====", data);
                    userData.push({
                        id: doc.id,
                        ...data
                    });
                });
                if (userData && userData.length > 0) {
                    res.send({
                        status:200,
                        message:"fetch data successfully",
                        data:userData[0]
                    })
                }else{
                    res.send({
                        status:400,
                        message:"Token Expired"
                    })
                }
            }
        }
    } catch (error) {
        console.log("Error in getting the user");
    }
})


//verify token
const verifyAccessToken = async(token) => {
      let result = jwt.verify(token, 'nodeReactApp', (err, res) => {
         console.log("+++++",err,res);
         return res;
    });
    return result
}




//check whether the email is present in db or not.
const validateEmail = async (email) => {
    let userData = [];
    let result = await db.collection('userAuth').where('email', "==", email).get();
    if (result.empty) {
        console.log('No Matching Documents');
        return;
    } else {
        result.forEach((doc) => {
            console.log(doc.id, '=>', doc.data());
            let data = doc.data();
            userData.push({
                id: doc.id,
                ...data
            });
        });
        console.log("userData===", userData);
        if (userData && userData.length > 0) return userData[0];
        else return;
    }
}


//update access token
const updateAccessToken = async (id, token) => {
    console.log("====what to update===", id, token);
    try {
        await db.collection('userAuth').doc(id).update({ token });
        console.log("success update")
    } catch (error) {
        console.log("Error while updating access token")
    }
}

