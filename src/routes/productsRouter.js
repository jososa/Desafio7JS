import { Router } from "express"
import { productManager } from '../dao/controllers/mongoDB/productManagerMongo.js'

const productsRouter = Router()

//Obtener productos
productsRouter.get("/", productManager.getAllProducts)

//Obtener producto por ID
productsRouter.get("/:pid", productManager.getProductById)

//Crear producto
productsRouter.post("/", productManager.addProduct)

//Modificar producto
productsRouter.put("/:prodId", productManager.updateProduct)

//Eliminar producto
productsRouter.delete("/:prodId", productManager.deleteProduct)

export default productsRouter