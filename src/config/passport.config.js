import passport from "passport"
import local from "passport-local"
import GitHubStrategy from "passport-github2"
import { environment } from "./config.js"
import usersModel from "../dao/models/usersModel.js"
import CartService from "../dao/services/carts.service.js"
import {createHash, isValidPassword} from "../utils.js"

const LocalStrategy = local.Strategy

const initializePassport = () => {

    //Estategia registro usuario
    passport.use("register", new LocalStrategy(
        { passReqToCallback:true, usernameField: "email" },
    async(req, username, password, done) => {
        const { first_name, last_name, email, age } = req.body
        try {
            const user = await usersModel.findOne({ email: username })
            if(user){
                console.log("El usuario ya se encuentra registrado")
                return done(null, false)
            }

            //const carrito = new CartManager()
            const cart = await CartService.createCart()

            const newUser = {
                first_name,
                last_name,
                email,
                age,
                password: createHash(password),
                cart: cart,
                role: "usuario"
            }
            const result = await usersModel.create(newUser)
            return done(null, result)
        } catch (error) {
            return done(error)
        }
    } ))


    //Estrategia de login
    passport.use(
        "login",
        new LocalStrategy(
          { usernameField: "email" },
          async (username, password, done) => {
            try {
              if (
                username === "adminCoder@coder.com" &&
                password === "adminCod3r123"
              ) {
                // Si las credenciales coinciden con el administrador predefinido creo un objeto con el los datos del administrador.
                const adminUser = {
                  first_name: "Admin",
                  last_name: "Coder",
                  email: "adminCoder@coder.com",
                  age: 30,
                  role: "admin",
                };
                return done(null, adminUser);
              }
    
              const user = await usersModel.findOne({ email: username });
              if (!user) return done(null, false);
              const valid = isValidPassword(user, password);
              if (!valid) return done(null, false);
    
              return done(null, user);
            } catch (error) {
              return done(error);
            }
          }
        )
      )

    //Login con github
    passport.use("github", new GitHubStrategy({
        clientID: environment.clientId,
        clientSecret: environment.clientSecret,
        callBackURL: environment.callbackURL,
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            const user = await usersModel.findOne({ email: profile._json.email })
            if(!user){
                const newUser = {
                    first_name: profile._json.name,
                    last_name: "",
                    age: 33,
                    email: profile._json.email,
                    password: "",
                    role: "usuario"
                }
                let createdUser = await usersModel.create(newUser)
                done(null, createdUser)
            } else{
                done(null, user)
            }
        } catch (error) {
            return done(error)
        }
    }))

    passport.serializeUser((user, done) => {
        if(user._id){
            done(null, user._id)
        } else{
            done(null,"admin")
        }
    })

    passport.deserializeUser(async (id, done) => {
        try {
            if(id === "admin"){
                const adminUser = {
                    first_name: "Admin",
                    last_name: "Coder",
                    email: "adminCoder@coder.com",
                    age: 33,
                    role: "admin"
                }
                done(null, adminUser)
            } else{
                let user = await usersModel.findById(id)
                done(null, user)
            }
        } catch (error) {
            done(error)
        }
    })

}

export default initializePassport