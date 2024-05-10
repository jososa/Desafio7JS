import { Router } from "express"
import { cartManager } from "../dao/controllers/mongoDB/cartManagerMongo.js"

const cartRouter = Router()

//Alta de carrito
cartRouter.post("/", cartManager.createCart)

//Obtener carritos
cartRouter.get("/", cartManager.getCarts)

//Obtener carrito por ID
cartRouter.get("/:cid", cartManager.getCartById)

//Agregar producto al carrito
cartRouter.post("/:cid/product/:pid", cartManager.addProductsToCart)

//Modificar carrito
cartRouter.put('/:cid', cartManager.updateProductsInCart)

//Actualiza la cantidad de un producto específico en el carrito
cartRouter.put('/:cid/products/:pid', cartManager.updateProductQuantity)

//Eliminar producto del carrito
cartRouter.delete('/:cid/products/:pid', cartManager.removeProductFromCart)

//Eliminar carrito
cartRouter.delete('/:cid', cartManager.clearCart)

export default cartRouter