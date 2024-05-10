import productsService from "../../services/products.service.js"

class ProductManager {

    async getAllProducts(req, res) {
        try {
            const products = await productsService.getAllProducts(req.query);
            res.status(200).send({ status: "success", payload: products });
          } catch (error) {
            console.log(error);
            res.status(500).send({ status: "error", error: error.message });
          }
      }

    addProduct = async (req, res) => {
        const newProduct = req.body;
        try {
          let result = await productsService.addProduct(newProduct)
          res.json({result})
        } catch (error) {
          res.status(500).json({ error: error.message })
        }
    }

    getProducts = async () => {
        try {
            let result = await productsModel.find().lean()
            return result
        } catch (error) {
            return error
        }
    }

    getProductById = async (req, res) => {
        const { pid } = req.params
        try {
          const product = await productsService.getProductById(pid)
          if (!product) {
            return res
              .status(404)
              .send({ status: "error", error: "Product not found" })
          }
          res.status(200).send({ status: "success", payload: product })
        } catch (error) {
          console.log(error)
          res.status(500).send({ status: "error", error: error.message })
        }
    }

    deleteProduct = async (req, res) => {
        const productId = req.params.prodId
        try {
          await productsService.deleteProduct(productId)
          res.json({ status: "Producto eliminado" })
        } catch (error) {
          res.status(400).json({ error: error.message })
        }
    }

    updateProduct = async (req, res) => {
        const productId = req.params.prodId
        const updatedFields = req.body
        try {
          const updatedProduct = await productsService.updateProduct(
            productId,
            updatedFields
          );
          res.json({ status: "Producto actualizado", updatedProduct })
        } catch (error) {
          res.status(400).json({ error: error.message })
        }
    }

}

export const productManager = new ProductManager() 