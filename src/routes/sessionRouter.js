import { Router } from "express"
//import userManager from "../dao/controllers/mongoDB/userManagerMongo.js"
import usersModel from "../dao/models/usersModel.js";
import utils, { createHash, isValidPassword } from "../utils.js"
import passport from "passport";

const sessionRouter = Router()

//Registro de Usuario
sessionRouter.post("/register", passport.authenticate('register',{failureRedirect:'/failregister'}), async(req,res) =>{
  res.status(201).send({status: "success", message: "Usuario registrado"})
})

sessionRouter.get("/failregister", async(req, res)=>{
  console.log('Error')
  res.send({error:"Fallo"})
})

//Login de Usuario
sessionRouter.post("/login", passport.authenticate('login',{failureRedirect:"/faillogin"}), async(req, res)=>{
  console.log("Entro al router")
  if(!req.user){
    return res.status(400).send('error')
  }
  req.session.user = {
    first_name: req.user.first_name,
    last_name: req.user.last_name,
    email: req.user.email,
    age: req.user.age,
    role: req.user.role
  }
  res.status(200).send({status:"success", payload: req.user})
})

sessionRouter.get("/faillogin", async(req, res)=>{
  console.log("error")
  res.send({error:"Fallo"})
})

sessionRouter.get("/github", passport.authenticate("github", {scope:["user:email"]}),
  async (req, res) => {
    res.send({status:"success", message: res})
  }
)

sessionRouter.get("/githubcallback", passport.authenticate("github", {failureRedirect:["/login"]}),
  async (req, res) => {
    req.session.user = req.user
    res.redirect("/")
  }
)

sessionRouter.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (!err) {
      res.send({ status: "success", message: "Sesión cerrada" })
    } else {
      res.send({ error: err })
    }
  })
})

sessionRouter.get("/current", async (req, res) => {
  if (!req.user) {
    res.status(403).send({ status: "Error", message: "Usuario no autenticado" })
  }
  res.send({ status: "success", payload: req.user })
});

//Restaurar password
sessionRouter.post("/restore", async (req, res) => {
  const {email, password} = req.body
  const user= await usersModel.findOne({email})

  if(!user){
    return res.status(400).send({status: "error", message:"No se encuentra usuario"})
  }

  const newPass = createHash(password)

  await usersModel.updateOne({_id: user._id}, {$set:{password:newPass}})

  res.send({status:"success", message: "Clave actualizada"})

})

export default sessionRouter