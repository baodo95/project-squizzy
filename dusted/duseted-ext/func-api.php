<?php 
	function add_restapi_controller( $controllers ){
		$controllers[] = 'restapi';
		return $controllers;
	}
	add_filter( 'json_api_controllers', 'add_restapi_controller');

	function set_restapi_controller_path(){
		return get_template_directory() . '/duseted-ext/duseted-restapi.php';
	}
	add_filter( 'json_api_restapi_controller_path', 'set_restapi_controller_path' );

	
?>