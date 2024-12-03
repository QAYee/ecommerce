<?php

session_start();
require_once($_SERVER["DOCUMENT_ROOT"]."/app/config/Directories.php");

require_once(ROOT_DIR."includes/header.php");

if(isset($_SESSION["mali"])){
    $messErr = $_SESSION["mali"];
    unset($_SESSION["mali"]);
}
if(isset($_SESSION["tama"])){
    $messSuc = $_SESSION["tama"];
    unset($_SESSION["tama"]);
}

include(ROOT_DIR. "app/product/get_product.php")
?>
<?php
require_once(ROOT_DIR."includes/navbar.php");
?>
    <!-- page guard  -->
    <?php require_once(ROOT_DIR."views/components/page-guard.php"); ?>

    
    <!-- Page Header -->
    <div class="container mt-5">
        <div class="d-flex justify-content-between align-items-center">
            <h2>Product List</h2>
            <!-- Add New Product Button -->
            <a href="<?php echo BASE_URL; ?>views/admin/products/add.php" class="btn btn-success">Add New Product</a>
        </div>

        <?php if(isset($messSuc)){ ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <strong><?php echo $messSuc; ?></strong> 
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                    <?php } ?>

                    <?php if(isset($messErr)){ ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <strong><?php echo $messErr; ?></strong> 
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                    <?php } ?>

        <p class="text-center">Manage all products in the catalog</p>
        <hr>
    </div>

    <!-- Product Cards Container -->
    <div class="container content mt-3">
        <div class="row">
            <!-- Sample Product Card -->
            <!-- Loop through each product and generate a card dynamically -->

            <?php 
            foreach($productList as $product){
            include(ROOT_DIR."views/components/product-card.php"); 
            }
            
            ?>  
            
        </div>
    </div>

    

    <!-- Bootstrap 5 JS Bundle -->
    <?php require_once(ROOT_DIR."/includes/footer.php")?>


