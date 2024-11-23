<?php

if(!isset($_SESSION)){
    session_start();
}

require_once(__DIR__."/../config/Directories.php"); //to handle folder specific path
include("..\config\DatabaseConnect.php"); //to access database connection
if(!isset($_SESSION["user_id"])){
    header("location: ".BASE_URL."login.php");
    exit;
}
$db = new DatabaseConnect(); //make a new database instance

if($_SERVER["REQUEST_METHOD"] == "POST"){
    $productId = htmlspecialchars($_POST["id"]);
    $quantity = htmlspecialchars($_POST["quantity"]);
    $userId   = $_SESSION["user_id"];
    
     //validate user input
    
    
    if (trim($productId) == "" || empty($productId)) { 
        $_SESSION["mali"] = "Product ID field is empty";
        header("location: ".BASE_URL."views/admin/products/product.php?id=".$productId);
        exit;
    }
    
    if (trim($quantity) == "" || empty($quantity) || $quantity < 1) { 
        $_SESSION["mali"] = "quantity field is empty";
        header("location: ".BASE_URL."views/admin/products/product.php?id=".$productId);
        exit; 
    }
    
    if (trim($userId) == "" || empty($userId)) { 
        $_SESSION["mali"] = "User ID field is empty";
        header("location: ".BASE_URL."views/admin/products/product.php?id=".$productId);
        exit;
    }
    
 
    try{
    //insert record to database
    $conn = $db->connectDB();
    $sql = "SELECT * from products WHERE products.id = :p_product_id";
    $stmt = $conn ->prepare($sql);
    $stmt ->bindParam('p_product_id', $productId);
    if(!$stmt->execute()){

    
    
    }
    $product = $stmt->fetch();

    
    $computedPrice =($product["unit_price"]* $quantity);
    
    $sql ="INSERT INTO carts(user_id,product_id,quantity,unit_price,total_price,created_at,updated_at) 
    VALUES ( :P_user_id, :P_product_id,:P_quantity, :P_unit_price, :P_total_price,NOW(),NOW())";

    $stmt= $conn->prepare($sql);    
    $data = [':P_user_id'           => $userId,
            ':P_product_id'         => $productId,
            ':P_quantity'           => $quantity,
            ':P_unit_price'         => $product["unit_price"],
            ':P_total_price'        => $computedPrice
            ];

         if(!$stmt->execute($data)){
            $_SESSION["mali"] = "failed to add to cart";
            header("location: ".BASE_URL."views/admin/products/product.php?id=".$productId);
            exit;

         }

        
        
         
     

         

         $_SESSION["tama"] = "added to cart successfully";
         header("location: ".BASE_URL."views/admin/products/product.php?id=".$productId);
        exit;
        

        } catch(PDOException $e){
            echo "Connection Failed" . $e->getMessage();
            $db=null;
        }

        
             

}




    