<?php
/*
Controller name: POTATO API Poll
Controller description: POTATO API Vote Poll And Rating
*/
//require 'smtpmail/PHPMailerAutoload.php';
include("smtpmail/src/PHPMailer.php");
include("smtpmail/src/Exception.php");
include("smtpmail/src/OAuth.php");
include("smtpmail/src/POP3.php");
include("smtpmail/src/SMTP.php");

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\OAuth;
use PHPMailer\PHPMailer\POP3;
use PHPMailer\PHPMailer\SMTP;

require("jwt.php");

class JSON_API_RESTAPI_Controller {
	
	public function duseted_changepassword() {
		global $json_api, $wpdb;
			$user_email = $json_api->query->user_email;
			/*validate email*/
			$isEmail = self::validateEmail($user_email);
			if(!$isEmail) {
				echo json_encode([
					'signal'=> 2,
					'message' => 'Email not regular, please enter email other!'
				]);
				exit();
			}
			$subject = "[Squizzy] Password Reset";
			//$message = "The email body content".'<br>';
			//$message .= wp_lostpassword_url().'<br>';
			$headers = array('Content-Type: text/html; charset=UTF-8');
			$attachments = array();
			$to = $user_email;
			$user = get_user_by('email', $user_email);
			$user_login = $user->user_login;
			//var_dump($user, $user_login);die;
			$adt_rp_key = get_password_reset_key( $user );
			$rp_link = '<a href="' . wp_login_url()."?action=rp&key=$adt_rp_key&login=".$user_login.'">'.wp_login_url()."?action=rp&key=$adt_rp_key&login=".$user_login.'</a>';
			$message .= "Click here to set the password for your account: <br>";
			$message .= $rp_link.'<br>';
			
			$data = wp_mail($to, $subject, strip_tags($message), $headers, $attachments);
			//$adt_rp_key = get_password_reset_key( $user );
			//var_dump(wp_lostpassword_url( get_permalink()));die;
			
			if($data){
				echo json_encode([
					'signal' => 1,
					'message' => "Send mail success"
				]);
				exit();
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => "Send mail false"
				]);
				exit();
			}
	}
	
	public function duseted_changepassword_old() {
			global $json_api, $wpdb;
			$user_email = $json_api->query->user_email;

			/*validate email*/
			$isEmail = self::validateEmail($user_email);
			if(!$isEmail) {
				echo json_encode([
						'signal'=> 2,
						'message' => 'Email not regular, please enter email other!'
					]);
				exit();
				/*$getUserByEmail = get_user_by('email', $user_email);
				if($getUserByEmail){
					echo json_encode([
						'signal'=> 2,
						'message' => 'email exist, please enter email other!'
					]);
					exit();
				}*/
			}/*else{
				echo json_encode([
						'signal'=> 2,
						'message' => 'Email not regular, please enter email other!'
					]);
				exit();
			}*/
			//var_dump($user_email);die;
			$mail = new PHPMailer(true); // create a new object
			$mail->IsSMTP(); // enable SMTP
			$mail->SMTPDebug = 0; // debugging: 1 = errors and messages, 2 = messages only
			$mail->SMTPAuth = true; // authentication enabled
			$mail->SMTPSecure = 'ssl'; // secure transfer enabled REQUIRED for Gmail or tls
			$mail->Host = "smtp.gmail.com";
			$mail->Port = 465; // or 587
			$mail->CharSet = "UTF-8";
			$mail->Username = "datyolo2000@gmail.com";
			$mail->Password = "xzycqxriqyywggih";
			$mail->SetFrom("datyolo2000@gmail.com");
			$mail->IsHTML(true);
			$mail->Subject = "Test sendMail 3";
			$mail->Body = "hello mdv";
			$mail->AddAddress($user_email);
			
			
			if(!$mail->Send()){
				echo json_encode([
					'signal' => 2,
					'message' => "Send mail false"
				]);
				exit();
			}else{
				echo json_encode([
					'signal' => 1,
					'message' => "Send mail success"
				]);
				exit();
			}
	}
	
	static function dusted_checkToken($username, $token){
		$resDatatoken = JWT::decode($token, "SCRET_KEY_SQUIZZY_TOKEN");
		if($resDatatoken['signal'] == 2) {
			return [
				'signal' => 2,
				'message' => $resDatatoken['message']
			];
		}else{
			$datatoken = $resDatatoken['data'];
			$dataExp = $datatoken->exp;
			//var_dump($dataExp);die;
			
			if((time() - $dataExp) > 7*24*3600*1000){
				return [
					'signal' => 2,
					'message' => 'token Expires'
				];
			}else{
				if($datatoken->username == $username){
					return [
						'signal' => 1,
						'message' => 'validate token success'
					];
				}else{
					return [
						'signal' => 2,
						'message' => 'token invalid'
					];
				}
			}
		}
	}
	
	public function duseted_user_login() {
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'users';
		
		$username = $json_api->query->user_name;
		$password = $json_api->query->pass_word;
		//$user_email = $json_api->query->user_email;
		
		$token = array();
		$token["username"] = $username;
		$token["exp"] = time() + 7*24*3600*1000;
		$jsonwebtoken = JWT::encode($token, "SCRET_KEY_SQUIZZY_TOKEN");
		
		//$token = md5("squizzy123products".$username);
		$user = get_userdatabylogin( $username );
		$userID = $user->ID;
		if(empty($username) || empty($password)) {
			echo json_encode([
				'signal'=>0,
				'message'=>'require params'
			]);
			exit();
		}
		//var_dump($jsonwebtoken);die;
		$get_username = $wpdb->get_results( 'SELECT user_login, user_pass ,user_email FROM wp_users WHERE id = ' . $userID  );
		if( $get_username ){			
			foreach( $get_username as $user ){
				//return $user->user_pass;
				//$wp_hasher = new PasswordHash(16, FALSE);
				$userdata = get_user_by('login', $username);
				$table_usermeta = $wpdb->prefix.'usermeta';	
				$metaKeyPoint = "point_quiz_user";
				$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$userID."' and meta_key ='".$metaKeyPoint."' " );
				
				//get user_email
				$user_email = $user->user_email;
				
				//var_dump(json_decode($get_UserMeta[0]->meta_value)[0]->current_question);die;
				if($get_UserMeta) {
					$dataMetaValueUser = json_decode($get_UserMeta[0]->meta_value);
					$sumPoint = 0;
					$quiz_complete = 0;
					for($i=0; $i<count($dataMetaValueUser); $i++){
						$sumPoint = $sumPoint + $dataMetaValueUser[$i]->total_point;
						if(($dataMetaValueUser[$i]->current_question) == ($dataMetaValueUser[$i]->total_question)){
							$quiz_complete = $quiz_complete + 1;
						}
					}
					if( wp_check_password( $password, $user->user_pass, $userID ) ) {
						$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$userID."' and meta_key = 'avatar_user' "  );
						if($get_usermetaAvatar){
							echo json_encode([
								'signal' => 1,
								'message'=> 'login success',
								'token' => $jsonwebtoken,
								'username' => $username,
								'email' => $user_email,
								'avatar' => $get_usermetaAvatar[0]->meta_value,
								'quiz_complete'=> $quiz_complete,
								'total_point' => $sumPoint
							]);
							exit();
						}else{
							echo json_encode([
								'signal' => 1,
								'message'=> 'login success',
								'token' => $jsonwebtoken,
								'username' => $username,
								'email' => $user_email,
								'avatar' => '',
								'quiz_complete'=> $quiz_complete,
								'total_point' => $sumPoint
							]);
							exit();
						}
					}
					else{
						echo json_encode([
							'signal' => 2,
							'message'=> 'Incorrect password'
						]);
						exit();
					}
				}else{
					if( wp_check_password( $password, $user->user_pass, $userID ) ) {
						$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$userID."' and meta_key = 'avatar_user' "  );
						if($get_usermetaAvatar){
							echo json_encode([
								'signal' => 1,
								'message'=> 'login success',
								'token' => $jsonwebtoken,
								'username' => $username,
								'avatar' => $get_usermetaAvatar[0]->meta_value,
								'email' => $user_email,
								'quiz_complete'=> 0,
								'total_point' => 0
							]);
							exit();
						}else{
							echo json_encode([
								'signal' => 1,
								'message'=> 'login success',
								'token' => $jsonwebtoken,
								'username' => $username,
								'avatar' => '',
								'email' => $user_email,
								'quiz_complete'=> 0,
								'total_point' => 0
							]);
							exit();
						}
					}
					else{
						echo json_encode([
							'signal' => 2,
							'message'=> 'Incorrect password'
						]);
						exit();
					}
				}
			}
		}else{
			echo json_encode([
				'signal' => 2,
				'message'=> 'Username does not exist'
			]);
			exit();
		}
	}
	
	public function duseted_user_registration(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'users';
		$username = $json_api->query->user_name;
		$password = $json_api->query->pass_word;
		$verypasswd = $json_api->query->very_passwd;
		$zipcode = $json_api->query->zip_code;
		$email = $json_api->query->email;
		$token = array();
		$token["username"] = $username;
		$token["exp"] = time() + 7*24*3600*1000;
		$jsonwebtoken = JWT::encode($token, "SCRET_KEY_SQUIZZY_TOKEN");
	
		if(empty($username) || empty($password) || empty($verypasswd) || empty($zipcode) || empty($email)){
			echo json_encode([
				'signal' => 0,
			    'message'=> 'require params'
			]);
			exit();
		}
		/*validate username*/
		$user = get_userdatabylogin( $username );
		if($user) {
			echo json_encode([
			    'signal'=> 2,
				'message' => 'Incorrect username, please enter try again!'
			]);
			exit();
		}
		
		/*validate email*/
		$isEmail = self::validateEmail($email);
		if($isEmail) {
			$getUserByEmail = get_user_by('email', $email);
			if($getUserByEmail){
				echo json_encode([
					'signal'=> 2,
					'message' => 'The details you have entered are incorrect please try again!'
				]);
				exit();
			}
		}else{
			echo json_encode([
					'signal'=> 2,
					'message' => 'Incorrect email format please try again!'
				]);
			exit();
		}
		
		if($password != $verypasswd){
			echo json_encode([
				'signal' => 2,
				'message' => 'password & very_passwd not value'
			]);
			exit();
		}
		$query_wp_users = $wpdb->insert($table_name , array(
			   "user_login" => $username,
			   "user_pass" => wp_hash_password($password),
			   "user_nicename" => $username,
			   "user_status" => 0,
			   "user_registered" => current_time( 'mysql' ),
			   "user_nicename" => $username,
			   "user_email" =>$email
			),
			array('%s','%s','%s','%d','%s','%s') 
		);
		if($query_wp_users){
			$user = get_userdatabylogin( $username );
			$userID = $user->data->ID;
			$table_usermeta = $wpdb->prefix."usermeta";
			$query_wp_usersmeta = $wpdb->insert('wp_usermeta' , array(
				   "user_id" => $userID,
				   "meta_key" => "post_code",
				   "meta_value" => $zipcode
				),
				array('%s','%s','%s')
			);	
			$dataUserRegistration = [
				'username' => $username,
				"email" => $email,
				'zip_code' => $zipcode,
				"token" => $jsonwebtoken
			];
			if($query_wp_usersmeta){
				$metaKeyPoint = "point_quiz_user";
				$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$userID."' and meta_key ='".$metaKeyPoint."' " );
				if(empty($get_UserMeta)){
					$dataUserRegistration['total_point'] = 0;
					$dataUserRegistration['quiz_complete'] = 0;
					echo json_encode([
						'signal' => 1,
						'message' => 'registration successful',
						'data' => $dataUserRegistration
					]);
					exit();
				}else{
					$dataMetaValueUser = json_decode($get_UserMeta[0]->meta_value);
					$sumPoint = 0;
					$quiz_complete = 0;
					for($i=0; $i<count($dataMetaValueUser); $i++){
						$sumPoint = $sumPoint + $dataMetaValueUser[$i]->total_point;
						if(($dataMetaValueUser[$i]->current_question) == ($dataMetaValueUser[$i]->total_question)){
							$quiz_complete = $quiz_complete + 1;
						}
					}
					$dataUserRegistration['total_point'] = $sumPoint;
					$dataUserRegistration['quiz_complete'] = $quiz_complete;
					echo json_encode([
						'signal' => 1,
						'message' => 'registration successful',
						'data' => $dataUserRegistration
					]);
					exit();
				}
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'post_code registration failed'
				]);
				exit();
			}
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'registration failed'
			]);
			exit();
		}
	}
	
	/*validate email*/
	 static function validateEmail($email) {
		  $isValid = true;
        $atIndex = strrpos($email, "@");
        if (is_bool($atIndex) && !$atIndex) {
            $isValid = false;
        } else {
            if (!preg_match('/^(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){255,})(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){65,}@)(?:(?:[\x21\x23-\x27\x2A\x2B\x2D\x2F-\x39\x3D\x3F\x5E-\x7E]+)|(?:\x22(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x21\x23-\x5B\x5D-\x7F]|(?:\x5C[\x00-\x7F]))*\x22))(?:\.(?:(?:[\x21\x23-\x27\x2A\x2B\x2D\x2F-\x39\x3D\x3F\x5E-\x7E]+)|(?:\x22(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x21\x23-\x5B\x5D-\x7F]|(?:\x5C[\x00-\x7F]))*\x22)))*@(?:(?:(?!.*[^.]{64,})(?:(?:(?:xn--)?[a-z0-9]+(?:-[a-z0-9]+)*\.){1,126}){1,}(?:(?:[a-z][a-z0-9]*)|(?:(?:xn--)[a-z0-9]+))(?:-[a-z0-9]+)*)|(?:\[(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){7})|(?:(?!(?:.*[a-f0-9][:\]]){7,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?)))|(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){5}:)|(?:(?!(?:.*[a-f0-9]:){5,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3}:)?)))?(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))(?:\.(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))){3}))\]))$/iD', $email)) {
                $isValid = false;
            }
            if (!preg_match("/^[a-zA-Z0-9]/i",$email)) {
                $isValid = false;
            }
            $domain = substr($email, $atIndex + 1);
            $local = substr($email, 0, $atIndex);
            $localLen = strlen($local);
            $domainLen = strlen($domain);
			
            //gmail khong chua ky tu dac biet ngoai tru "."
            if ($domain == "gmail.com") {
                if (preg_match('/[\'^!£$%&*()}{@#~?><>,|=_+¬-]/', $local)) {
                    $isValid = false;
                }
            }
            if (in_array($domain, ['yahoo.com', 'yahoo.com.vn'])) {
                if (( preg_match('/[\'^!£$%&*()}{@#~?><>,|=+¬-]/', $local) || substr_count($local,'.') >=2)) {
                    $isValid = false;
                }
                if (!preg_match("/^[a-zA-Z]/i",$email)) {
                    $isValid = false;
                }
            }
            //microsoft mail khong chua ky tu dac biet ngoai tru "."  "_"  "-"
            if (in_array($domain,['outlook.com','hotmail.com','live.com'])) {
                if (preg_match('/[\'^!£$%&*()}{@#~?><>,|=+¬]/',$local)) {
                    $isValid = false;
                }
            }
            if ($localLen < 1 || $localLen > 64) {
                $isValid = false;
            } else if ($domainLen < 1 || $domainLen > 255) {
                $isValid = false;
            } else if ($local[0] == '.' || $local[$localLen - 1] == '.') {
                $isValid = false;
            } else if (preg_match('/\\.\\./', $domain)) {
                $isValid = false;
            }
        }
        return $isValid;
	}
	
	public function duseted_user_new_password(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'users';
		$username = $json_api->query->user_name;
		$newpassword =  $json_api->query->newpassword;
		$confirm_newpassword =  $json_api->query->confirm_newpassword;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		if(empty($username) || empty($newpassword) || empty($confirm_newpassword) || empty($token)){
			echo json_encode([
				'signal' => 0,
			    'message'=> 'require params'
			]);
			exit();
		}
		if($newpassword != $confirm_newpassword){
			echo json_encode([
				'signal' => 0,
			    'message'=> 'newpassword & confirm_newpassword not same value'
			]);
			exit();
		}
		$query_wp_users = $wpdb->update($table_name , array(
			   "user_pass" => wp_hash_password($newpassword),
			),
			array('user_login' => $username),
			array('%s'),
			array('%s')			
		);
		if($query_wp_users){
			echo json_encode([
				'signal' => 1,
			    'message'=> 'new password registered'
			]);
			exit();
		}else {
			echo json_encode([
				'signal' => 2,
			    'message'=> 'new password failed, try again'
			]);
			exit();
		}
	}
	
	/*Cụm api avatar*/
	/*API create avatar*/
	public function duseted_createAvatar(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'usermeta';
		$username = $json_api->query->user_name;	
		$avatar = $json_api->query->url_avatar;	
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($username) || empty($avatar) || empty($token)){
			echo json_encode([
			  'signal' => 0,
			  'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		if($user) {
			$userID = $user->ID;
			$dataAvatar = $wpdb->insert( 
				$table_name , 
				array( 
				    'user_id' => $userID,
					'meta_key' => 'avatar_user',
					'meta_value' => $avatar    //string
				), 
				array( '%d', '%s','%s') 
			);
			if($dataAvatar){
				echo json_encode([
				  'signal' => 1,
				  'message' => 'create avatar user success'
				]);
				exit();
			}else{
				echo json_encode([
				  'signal' => 2,
				  'message' => 'could not create avatar'
				]);
				exit();
			}
		}else{
			echo json_encode([
			  'signal' => 2,
			  'message' => 'user does not exist'
			]);
			exit();
		}
	}
	
	/*API update avatar*/
	public function duseted_updateAvatar(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'usermeta';
		$username = $json_api->query->user_name;	
		$avatar = $json_api->query->url_avatar;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}		
		if(empty($username) || empty($avatar) || empty($token)){
			echo json_encode([
			  'signal' => 0,
			  'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		//var_dump($user->ID, $username, $avatar);die;
		if($user) {
			$userID = $user->ID;
			$get_usermeta = $wpdb->get_results( "SELECT * FROM ". $table_name ." WHERE user_id = ' ".$userID." ' and meta_key = 'avatar_user' "  );
			if($get_usermeta){
				$dataAvatar = $wpdb->update( 
					$table_name , 
					array( 
						'meta_value' => $avatar    //string
					), 
					array( 'user_id' => $userID , 'meta_key' => 'avatar_user'), 
					array( 
						'%s' // value1
					), 
					array( '%d', '%s') 
				);
				if($dataAvatar){
					echo json_encode([
					  'signal' => 1,
					  'message' => 'avatar updated'
					]);
					exit();
				}else{
					echo json_encode([
					  'signal' => 2,
					  'message' => 'could not create avatar'
					]);
					exit();
				}
			}else{
				$dataAvatar = $wpdb->insert( 
					$table_name , 
					array( 
						'user_id' => $userID,
						'meta_key' => 'avatar_user',
						'meta_value' => $avatar    //string
					), 
					array( '%d', '%s','%s') 
				);
				if($dataAvatar){
					echo json_encode([
					  'signal' => 1,
					  'message' => 'avatar updated'
					]);
					exit();
				}else{
					echo json_encode([
					  'signal' => 2,
					  'message' => 'could not create avatar'
					]);
					exit();
				}
			}
		}else{
			echo json_encode([
			  'signal' => 2,
			  'message' => 'user does not exists'
			]);
			exit();
		}
	}
	
	//get avatar
	public function duseted_getAvatar(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'usermeta';
		$username = $json_api->query->user_name;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}	
		if(empty($username) || empty($token)){
			echo json_encode([
			  'signal' => 0,
			  'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		if($user){
			$userID = $user->ID;
			$get_usermeta = $wpdb->get_results( "SELECT * FROM ". $table_name ." WHERE user_id = ' ".$userID." ' and meta_key = 'avatar_user' "  );
			//var_dump($get_usermeta);die;
			if($get_usermeta){
				echo json_encode([
					'signal' => 1,
					'message' => 'get avatar success',
					'avatar_user' => $get_usermeta[0]->meta_value
				]);
				exit();
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'get avatar failed'
				]);
				exit();
			}
		}else {
			echo json_encode([
			  'signal' => 2,
			  'message' => 'user does not exists'
			]);
			exit();
		}
	}
	
	//api check user_name
	public function duseted_checkUserName(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'users';	
		$username = $json_api->query->user_name;
		//var_dump($username);die;
		$user = get_userdatabylogin($username);
		if($user){
			echo json_encode([
				'signal' => 0,
				'message' => 'username exists'
			]);
			exit();
		}else{
			echo json_encode([
				'signal' => 1,
				'message' => 'success username does not exists'
			]);
			exit();
		}
	}
	
	//api change username
	public function duseted_changeUsername() {
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'users';	
		$username_old = $json_api->query->user_name_old;
		$username_new = $json_api->query->user_name_new;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username_old, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		if(empty($username_old) || empty($username_new) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		
		$user_old = get_userdatabylogin( $username_old );
		$user_name_new = get_userdatabylogin( $username_new );
		if($user_name_new) {
			echo json_encode([
				'signal' => 2,
				'message' => 'new username invalid'
			]);
			exit();
		}else {
			if($user_old) {
				$userID = $user_old->ID;
				$dataUser = $wpdb->update( 
					$table_name , 
					array( 
						'user_login' => $username_new    //string
					), 
					array( 'ID' => $userID), 
					array( 
						'%s' // value1
					), 
					array('%d') 
				);
				if($dataUser){
					$token = array();
					$token["username"] = $username_new;
					$token["exp"] = time() + 7*24*3600*1000;
					$jsonwebtoken = JWT::encode($token, "SCRET_KEY_SQUIZZY_TOKEN");
					echo json_encode([
					   'signal' => 1,
					   'message' => 'username update successful',
					   'username' => $username_new, 
					   'token' => $jsonwebtoken
					]);
					exit();
				}else{
					echo json_encode([
					  'signal' => 2,
					  'message' => 'username updated failed'
					]);
					exit();
				}
			}else{
				echo json_encode([
				  'signal' => 2,
				  'message' => 'user_old not invalid'
				]);
				exit();
			}
		}
	}
	
	/*API get list course by user*/
	public function duseted_getlistCourseByUser(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'posts';
		$username = $json_api->query->user_name;

		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}	
		if(empty($username) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		
		$user = get_userdatabylogin( $username );
		$userID = $user->ID;
		$get_listdata = $wpdb->get_results( "SELECT * FROM ". $table_name ."  WHERE post_author = ' ". $userID." '  and comment_status='open' and post_parent='0' and menu_order='0' and  post_status='publish' and post_type='sfwd-courses' ");
		$listCourse = [];
		foreach( $get_listdata as $listdata ){
			$dataListCourse = [
				'id' => $listdata->ID,
				'post_author' => $listdata->post_author,
				'post_title' => $listdata->post_title,
				'post_content' => $listdata->post_content,
				'post_status' => $listdata->post_status,
				'post_excerpt' => $listdata->post_excerpt,
				'post_date' => $listdata->post_date,
				'post_modified' => $listdata->post_modified,
				'post_type' => $listdata->post_type,
				'post_parent' => $listdata->post_parent,
				'guid' => $listdata->guid,
				'post_content_filtered' => $listdata->post_content_filtered,
				'comment_count' => $listdata->comment_count
			];
			array_push($listCourse,$dataListCourse);
		}
		
		if(count($listCourse) == 0){
			echo json_encode([
				'signal' => 3,
			    'message'=> 'get list course not value'
			]);
			exit();
		}elseif(count($listCourse) > 0){
			echo json_encode([
				'signal' => 1,
			    'message'=> 'get list course success',
				'datalist' => $listCourse
			]);
			exit();
		}else{
			echo json_encode([
				'signal' => 0,
			    'message'=> 'get list course false'
			]);
			exit();
		}
	}

	/*get details of course*/
	public function duseted_getDetailsCourse(){
		global $json_api, $wpdb;
		$table_name = $wpdb->prefix.'posts';
		$IdCourse = $json_api->query->id_course;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($IdCourse) || empty($token) || empty($username)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$get_detail_Course = $wpdb->get_results( "SELECT * FROM ". $table_name ." WHERE id = ' ".$IdCourse." ' "  );
		if($get_detail_Course) {
			$dataCourse = [
				'id' => $get_detail_Course[0]->ID,
				'post_author' => $get_detail_Course[0]->post_author,
				'post_title' => $get_detail_Course[0]->post_title,
				'post_content' => $get_detail_Course[0]->post_content,
				'post_status' => $get_detail_Course[0]->post_status,
				'post_excerpt' => $get_detail_Course[0]->post_excerpt,
				'post_date' => $get_detail_Course[0]->post_date,
				'post_modified' => $get_detail_Course[0]->post_modified,
				'post_type' => $get_detail_Course[0]->post_type,
				'post_parent' => $get_detail_Course[0]->post_parent,
				'guid' => $get_detail_Course[0]->guid,
				'post_content_filtered' => $get_detail_Course[0]->post_content_filtered,
				'comment_count' => $get_detail_Course[0]->comment_count
			];
			echo json_encode([
				'signal' => 1,
			    'message'=> 'get details course success',
				'dataDetail' => $dataCourse
			]);
			exit();
		}else{
			echo json_encode([
				'signal' => 0,
			    'message'=> 'get detail course false'
			]);
			exit();
		}
	}	
	
	
	/*Add quizz
	 - add quiz_master
	 - add quiz_question
	*/
	static function getToplistDataQuizMaster(){
		$dataMaster = array(
			'toplistDataAddPermissions' => 1,
			'toplistDataSort' => 1,
			'toplistDataAddMultiple' => false,
			'toplistDataAddBlock' => 1,
			'toplistDataShowLimit' => 1,
			'toplistDataShowIn' => 0,
			'toplistDataCaptcha' => false,
			'toplistDataAddAutomatic' => false
		);
		return serialize($dataMaster);
	}
	
	public function duseted_AddQuiz(){
		/*Add Quiz master*/
		global $json_api, $wpdb;
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$table_name_posts = $wpdb->prefix.'posts';
		$table_name_postmeta = $wpdb->prefix.'postmeta';
		$username = $json_api->query->user_name;
		$name_quiz = $json_api->query->name_quiz;	
		$lat = $json_api->query->latz;	
		$long = $json_api->query->longz;
		//$status = $json_api->query->status;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}		
		//var_dump($name_quiz,$lat,$long,$username);die;
		if(empty($name_quiz) || empty($lat) || empty($long) || empty($username) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		$user_id = $user->ID;
		
		//checknameQuizz ko cho add
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$get_dataQuizMaster = $wpdb->get_results( "SELECT * FROM ". $table_name_master ." WHERE name = '".$name_quiz."' "  );	
		if($get_dataQuizMaster){
			echo json_encode([
				'signal' => 2,
				'message' => 'nameQuiz already exist, please enter another name!'
			]);
			exit();
		}
		
		//var_dump($table_name_master, $lat, $long);die;
		//Thực hiện create postmeta
		/*
		$post_id = 60;
		$meta_key = "_sfwd-quiz";
		$meta_value = wp_unslash($meta_value);
		$meta_subtype = self :: apply_filters( "get_object_subtype_{$object_type}", "sfwd-quiz", $post_id);
		$meta_value = sanitize_meta( $meta_key, $meta_value, $meta_type, $meta_subtype );
		*/
		///Tạo post data tại đây
		$dataPostQuiz = array(
			"post_author" => $user_id,
			"post_content" => "",
			"post_date" => current_time( "mysql" ),
			"post_date_gmt"=> current_time( "mysql" ), 
			"post_title" => $name_quiz,
			"post_excerpt" => "",
			"post_status" => "private",
			"comment_status" => "open",
			"ping_status" => "closed",
			"post_password" => "",
			"post_name" => $name_quiz,
			"to_ping" => "",
			"pinged" => "",
			"post_modified" => current_time( "mysql" ),
			"post_modified_gmt" => current_time( "mysql" ),
			"post_content_filtered"=>"",
			"post_parent" => 0,
			"menu_order" => 0,
			"post_type" => "sfwd-quiz", 
			"guid" => "",
			"post_mime_type" => "",
			"comment_count" => 0
		);
		$query_wp_dataPost = $wpdb->insert($table_name_posts , $dataPostQuiz,
			array(
					'%d', '%s', '%s', '%s', '%s', 
					'%s', '%s', '%s', '%s', '%s', 
					'%s', '%s', '%s','%s', '%s',
					'%s','%d','%d', '%s', '%s','%s', '%d'
				)
		);
		if($query_wp_dataPost) {
			$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_posts ." WHERE post_title = '".$name_quiz."' "  );
			//Thực hiện update gui
			$guid = "http://sq.dusted.com.au/?post_type=sfwd-quiz&p=".$get_dataPost[0]->ID;
			$updatedGui = $wpdb->update( 
				$table_name_posts , 
				array( 
					'guid' => $guid    //string
				), 
				array( 'ID' => $get_dataPost[0]->ID), 
				array( 
					'%s' // value1
				), 
				array( '%s') 
			);
			if($updatedGui) {
				$dataQuizMaster = array(
					"name" => $name_quiz,
					"text" => "",
					"result_text" => "",
					"result_grade_enabled" => (int)(false),
					"title_hidden" => (int)(false),
					"btn_restart_quiz_hidden" => (int)(false),
					"btn_view_question_hidden" => (int)(false),
					"question_random" => (int)(false),
					"answer_random" => (int)(false),
					"time_limit" => (int)(0),			
					"statistics_on" => (int)(false),
					"statistics_ip_lock" => (int)(0),
					"show_points" => (int)(false),
					"quiz_run_once" => (int)(false),
					"quiz_run_once_type" => (int)(1),
					"quiz_run_once_cookie" => (int)(false),
					"quiz_run_once_time" => (int)(0),
					"numbered_answer" => (int)(false),
					"hide_answer_message_box" => (int)(false),
					"disabled_answer_mark" => (int)(false),
					"show_max_question" => (int)(false),
					"show_max_question_value" => (int)(1),
					"show_max_question_percent" => (int)(false),
					"toplist_activated" => (int)(false),
					"toplist_data" => self::getToplistDataQuizMaster(),
					"show_average_result" => (int)(false),
					"prerequisite" => (int)(false),
					"quiz_modus" => (int)(0),
					"show_review_question" => (int)(false),
					"quiz_summary_hide" => (int)(false),
					"skip_question_disabled" => (int)(false),
					"email_notification" => (int)(0),
					"user_email_notification" => (int)(false),
					"show_category_score" => (int)(false),
					"hide_result_correct_question" => (int)(false),
					"hide_result_quiz_time" => (int)(false),
					"hide_result_points" => (int)(false),
					"autostart" => (int)(false),
					"forcing_question_solve" => (int)(false),
					"hide_question_position_overview" => (int)(false),
					"hide_question_numbering" => (int)(false),
					"form_activated" => (int)(false),
					"form_show_position" =>(int)(0),
					"start_only_registered_user" => (int)(false),
					"questions_per_page" => (int)(0),
					"sort_categories" => (int)(false),
					"show_category" => (int)(false)
				);	
				$query_wp_QuizMaster = $wpdb->insert($table_name_master , $dataQuizMaster,
					array(
						'%s', '%s', '%s', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%s', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d'
					)
				);
				if($query_wp_QuizMaster){	
					$get_dataQuizMaster = $wpdb->get_results( "SELECT * FROM ". $table_name_master ." WHERE name = '".$name_quiz."' "  );
					//var_dump($get_dataQuizMaster[0]->id,$get_dataQuizMaster);die;
					//Thực hiện create postmeta	
					//create key sfwd-quiz
					$dataMetavalue = [
						"sfwd-quiz_quiz_materials"=>"",
						"sfwd-quiz_repeats" => "",
						"sfwd-quiz_threshold" => "0.8",
						"sfwd-quiz_passingpercentage"=>"80",
						"sfwd-quiz_course" => "0",
						"sfwd-quiz_lesson" => "0",
						"sfwd-quiz_certificate"=>"0",
						"sfwd-quiz_quiz_pro" => $get_dataQuizMaster[0]->id
					];
					$dataPostMetaQuiz = array(
						"post_id" => $get_dataPost[0]->ID,
						"meta_key" => "_sfwd-quiz",
						"meta_value" => serialize($dataMetavalue)
					);
					$query_wp_dataPostMetaQuiz = $wpdb->insert($table_name_postmeta , $dataPostMetaQuiz,
						array(
							'%d', '%s', '%s'
						)
					);
					if($query_wp_dataPostMetaQuiz) {
						//create key sfwd-quiz
						$dataPostMetaLat = array(
							"post_id" => $get_dataPost[0]->ID,
							"meta_key" => "lat",
							"meta_value" => $lat
						);
						$query_wp_dataPostMetaLat = $wpdb->insert($table_name_postmeta , $dataPostMetaLat,
							array(
								'%d', '%s', '%s'
							)
						);
						if($query_wp_dataPostMetaLat){
							$dataPostMetaLong = array(
								"post_id" => $get_dataPost[0]->ID,
								"meta_key" => "long",
								"meta_value" => $long
							);
							$query_wp_dataPostMetaLong = $wpdb->insert($table_name_postmeta , $dataPostMetaLong,
								array(
									'%d', '%s', '%s'
								)
							);
							if($query_wp_dataPostMetaLong) {
								echo json_encode([
									'signal' => 1,
									'message' => 'create quizz success',
									'quiz_id' => $get_dataQuizMaster[0]->id,
									'name' => $get_dataQuizMaster[0]->name
								]);
								exit();
							}else {
								echo json_encode([
									'signal' => 2,
									'message' => 'create quizz longz false'
								]);
								exit();
							}
						}
					}			
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'create quizz latz false'
					]);
					exit();
				}	
			}else{
				$dataQuizMaster = array(
					"name" => $name_quiz,
					"text" => "",
					"result_text" => "",
					"result_grade_enabled" => (int)(false),
					"title_hidden" => (int)(false),
					"btn_restart_quiz_hidden" => (int)(false),
					"btn_view_question_hidden" => (int)(false),
					"question_random" => (int)(false),
					"answer_random" => (int)(false),
					"time_limit" => (int)(0),			
					"statistics_on" => (int)(false),
					"statistics_ip_lock" => (int)(0),
					"show_points" => (int)(false),
					"quiz_run_once" => (int)(false),
					"quiz_run_once_type" => (int)(1),
					"quiz_run_once_cookie" => (int)(false),
					"quiz_run_once_time" => (int)(0),
					"numbered_answer" => (int)(false),
					"hide_answer_message_box" => (int)(false),
					"disabled_answer_mark" => (int)(false),
					"show_max_question" => (int)(false),
					"show_max_question_value" => (int)(1),
					"show_max_question_percent" => (int)(false),
					"toplist_activated" => (int)(false),
					"toplist_data" => self::getToplistDataQuizMaster(),
					"show_average_result" => (int)(false),
					"prerequisite" => (int)(false),
					"quiz_modus" => (int)(0),
					"show_review_question" => (int)(false),
					"quiz_summary_hide" => (int)(false),
					"skip_question_disabled" => (int)(false),
					"email_notification" => (int)(0),
					"user_email_notification" => (int)(false),
					"show_category_score" => (int)(false),
					"hide_result_correct_question" => (int)(false),
					"hide_result_quiz_time" => (int)(false),
					"hide_result_points" => (int)(false),
					"autostart" => (int)(false),
					"forcing_question_solve" => (int)(false),
					"hide_question_position_overview" => (int)(false),
					"hide_question_numbering" => (int)(false),
					"form_activated" => (int)(false),
					"form_show_position" =>(int)(0),
					"start_only_registered_user" => (int)(false),
					"questions_per_page" => (int)(0),
					"sort_categories" => (int)(false),
					"show_category" => (int)(false)
				);	
				$query_wp_QuizMaster = $wpdb->insert($table_name_master , $dataQuizMaster,
					array(
						'%s', '%s', '%s', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%s', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d', '%d', '%d', '%d', 
						'%d', '%d'
					)
				);
				if($query_wp_QuizMaster){	
					$get_dataQuizMaster = $wpdb->get_results( "SELECT * FROM ". $table_name_master ." WHERE name = '".$name_quiz."' "  );
					//var_dump($get_dataQuizMaster[0]->id,$get_dataQuizMaster);die;
					//Thực hiện create postmeta	
					//create key sfwd-quiz
					$dataMetavalue = [
						"sfwd-quiz_quiz_materials"=>"",
						"sfwd-quiz_repeats" => "",
						"sfwd-quiz_threshold" => "0.8",
						"sfwd-quiz_passingpercentage"=>"80",
						"sfwd-quiz_course" => "0",
						"sfwd-quiz_lesson" => "0",
						"sfwd-quiz_certificate"=>"0",
						"sfwd-quiz_quiz_pro" => $get_dataQuizMaster[0]->id
					];
					$dataPostMetaQuiz = array(
						"post_id" => $get_dataPost[0]->ID,
						"meta_key" => "_sfwd-quiz",
						"meta_value" => serialize($dataMetavalue)
					);
					$query_wp_dataPostMetaQuiz = $wpdb->insert($table_name_postmeta , $dataPostMetaQuiz,
						array(
							'%d', '%s', '%s'
						)
					);
					if($query_wp_dataPostMetaQuiz) {
						//create key sfwd-quiz
						$dataPostMetaLat = array(
							"post_id" => $get_dataPost[0]->ID,
							"meta_key" => "lat",
							"meta_value" => $lat
						);
						$query_wp_dataPostMetaLat = $wpdb->insert($table_name_postmeta , $dataPostMetaLat,
							array(
								'%d', '%s', '%s'
							)
						);
						if($query_wp_dataPostMetaLat){
							$dataPostMetaLong = array(
								"post_id" => $get_dataPost[0]->ID,
								"meta_key" => "long",
								"meta_value" => $long
							);
							$query_wp_dataPostMetaLong = $wpdb->insert($table_name_postmeta , $dataPostMetaLong,
								array(
									'%d', '%s', '%s'
								)
							);
							if($query_wp_dataPostMetaLong) {
								echo json_encode([
									'signal' => 1,
									'message' => 'create quizz success',
									'quiz_id' => $get_dataQuizMaster[0]->id,
									'name' => $get_dataQuizMaster[0]->name
								]);
								exit();
							}else {
								echo json_encode([
									'signal' => 2,
									'message' => 'create quizz longz false'
								]);
								exit();
							}
						}
					}			
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'create quizz latz false'
					]);
					exit();
				}	
			}				
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'create post false'
			]);
			exit();
		}
	}
	
	
	/*get MaxSort*/
	static function getMaxSort(){
		global $json_api, $wpdb;
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$quizId = $json_api->query->quiz_id;
		$get_dataPost = $wpdb->get_results( "SELECT MAX(sort) AS max_sort FROM ". $table_name_question ." WHERE quiz_id = '".$quizId."' and online=1 "  );
		return $get_dataPost[0]->max_sort;
	}
	
	static function createAnswerData($value) {
		if ( is_array( $value ) ) {
			$answer_import_array = array();
			foreach( $value as $answer_item ) {
				if ( is_array( $answer_item ) ) {
					$answer_import = new WpProQuiz_Model_AnswerTypes();
					$answer_import->set_array_to_object( $answer_item );
					//var_dump($answer_import);die;
					array_push($answer_import_array, $answer_import);
				}//else if ( instanceof($answer_item, 'WpProQuiz_Model_AnswerTypes' ) ) {
					//array_push($answer_import_array, $answer_import);
				//}
			}
		}
		//var_dump($answer_import_array);die;
		return serialize($answer_import_array);
	}

	//static get name Quiz by quiz_id
	static function dusted_getNameByQuizId($quiz_id){
		global $json_api, $wpdb;
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$table_name_posts = $wpdb->prefix.'posts';
		$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE id='".$quiz_id."' ");
		$nameQuiz = $get_ProQuizMaster[0]->name;
		return $nameQuiz;
	}
	
	/*AddQuestion*/
	public function duseted_AddQuestion(){
		global $json_api, $wpdb;
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$quizId = $json_api->query->quiz_id;
		$username = $json_api->query->username;
		$question_title = $json_api->query->question_title;
		//$points = $json_api->query->points;
		$question_question = $json_api->query->question_question;
		$answer_type = $json_api->query->answer_type;
		$answer_question = $json_api->query->answer_question;
		$token =  $json_api->query->token;
		$image =  $_FILES['image'];
		$tmp_image = $image['tmp_name'];
		$name_image = $image['name'];
		$error_image = $image['error'];
		//var_dump($image['type'], $tmp_image, $name_image, $error_image );die;
		
		//set point default = 5;
		$points = "5";
		//var_dump($points);die;
		
		$checktoken = self::dusted_checkToken($username, $token);	
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		$type_image = $image['type'];
		//var_dump('quizId : '.$quizId);die;
		//var_dump('quizId : '.$quizId, 'question_title:'.$question_title,'answer_type : '.$answer_type,'answer_question:'.$answer_question,'token : '.$token,'username: '.$username,'image : '.$image);die;
		if(empty($quizId) || empty($question_title) || empty($points)||empty($question_question)||empty($answer_type)||empty($answer_question) || empty($token) || empty($username) || empty($image)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		//var_dump("ahihi");die;
		if(!in_array($type_image, ["image/jpeg","image/jpg","image/png"])){
			echo json_encode([
				'signal' => 2,
				'message' => 'invalid image format please use png, jpg, jpeg'
			]);
			exit();
		}
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE id='".$quizId."' ");
		if(!$get_ProQuizMaster){
			echo json_encode([
				'signal' => 2,
				'message' => 'quiz_id invalid'
			]);
			exit();
		}
		
		/*check name image already exist*/
		$name_image = $image['name'];
		$table_postmeta = $wpdb->prefix.'postmeta';
		$get_UserMetaLat = $wpdb->get_results( "SELECT * FROM ". $table_postmeta ." WHERE meta_key= '_wp_attached_file' AND meta_value='". $name_image ."' " );
		if($get_UserMetaLat){
			/*Thuc hien update image*/
			echo json_encode([
				'signal' => 2,
				'message' => 'image name already exists. Please use another name'
			]);	
			exit();
		}
		$tmp_image = $image['tmp_name'];
		$name_image = $image['name'];
		$error_image = $image['error'];
		$current_month = date('m');
		$current_year = date('Y');
		$current_time_img = $current_year."/".$current_month."/";
		if($error_image > 0) {
			echo json_encode([
				'signal' => 2,
				'message' => 'upload file image error'
			]);
			exit();
		}else{
			// Upload file
			//$domain = 'http://sq.dusted.com.au/wp-content/uploads/2019/01/';
			$domain = 'http://sq.dusted.com.au/wp-content/uploads/'.$current_time_img;
			if ( ! function_exists( 'wp_handle_upload' ) ) {
				require_once( ABSPATH . 'wp-admin/includes/file.php' );
			}
			$upload_overrides = array( 'test_form' => false );
			//if(!wp_handle_upload($image, $upload_overrides, '"'.$current_year."/".$current_month.'"')){
			if(!wp_handle_upload($image, $upload_overrides,  $current_year."/".$current_month)){
				echo json_encode([
					'signal' => 2,
					'message' => 'upload file image error'
				]);
				exit();
			}
		}
		//var_dump($type_image, $name_image, $tmp_image);die;
		//getnameQuiz By QuizId
		//$NameQuiz = self :: dusted_getNameByQuizId($quizId);
		//var_dump("ahihi");die;
		//var_dump($quizId,$question_title,$points,$question_question,$answer_type,$answer_question);die;
		
		$answer_question = json_decode(stripslashes($answer_question));
		$Data_answer_question = [];
		foreach($answer_question as $answers){
			$data_answer = [
				'_answer' => $answers->answer,
				'_points' => $points,
				'_correct' => $answers->correct,
			];
			array_push($Data_answer_question, $data_answer);
		}
		//var_dump($Data_answer_question);die;
		$ItemQuestion = [
			'quiz_id' => $quizId,
			'online' => 1,
			'sort' => (self::getMaxSort($quizId)) + 1,
			'title' => $question_title,
			'points' => $points,
			'question' => $question_question,
			'correct_msg' =>'',
			'incorrect_msg' => '',
			'correct_same_text' => (int)(false),
			'tip_enabled' => (int)(false),
			'tip_msg' => '',
			'answer_type' => $answer_type,
			'show_points_in_box' => (int)(false),
			'answer_points_activated' => (int)(false),
			'answer_data' => self::createAnswerData($Data_answer_question),
			'category_id' => 0,
			'answer_points_diff_modus_activated' => (int)(false),
			'disable_correct' => (int)(false),
			'matrix_sort_answer_criteria_width' => 20
		];
		$query_wp_QuizMaster = $wpdb->insert($table_name_question , $ItemQuestion,
			array('%d', '%d', '%d', '%s', '%d', 
				  '%s', '%s', '%s', '%d', '%d', 
				  '%s', '%s', '%d', '%d', '%s', 
				  '%d', '%d', '%d', '%d')
		);
		
		if($query_wp_QuizMaster){
			$user = get_userdatabylogin( $username );
			$userID = $user->data->ID;
			$table_name_posts = $wpdb->prefix.'posts';
			$nameQuiz = $get_ProQuizMaster[0]->name;
			$get_PostQuiz = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '". $nameQuiz."' and comment_status='open' and post_parent='0' and menu_order='0' and post_type='sfwd-quiz' ");
			//get parentId By QuizName (table post)
			$parrentId = $get_PostQuiz[0]->ID;
			//Tiep tuc thuc hien insert vao bang post
			///Tạo post data tại đây
			$dataPostQuizImage = array(
				"post_author" => $userID,
				"post_content" => "",
				"post_date" => current_time( "mysql" ),
				"post_date_gmt"=> current_time( "mysql" ), 
				"post_title" => $name_image,
				"post_excerpt" => $name_image,
				"post_status" => "publish",
				"comment_status" => "open",
				"ping_status" => "closed",
				"post_password" => "",
				"post_name" => $name_image,
				"to_ping" => "",
				"pinged" => "",
				"post_modified" => current_time( "mysql" ),
				"post_modified_gmt" => current_time( "mysql" ),
				"post_content_filtered"=>"",
				"post_parent" => $parrentId,
				"menu_order" => 0,
				"post_type" => "attachment", 
				//"guid" => "http://sq.dusted.com.au/wp-content/uploads/2019/01/".$name_image,
				"guid" => "http://sq.dusted.com.au/wp-content/uploads/".$current_time_img.$name_image,
				"post_mime_type" => $image['type'],
				"comment_count" => 0
			);
			$query_wp_dataPost = $wpdb->insert($table_name_posts , $dataPostQuizImage,
				array(
						'%s', '%s', '%s', '%s', '%s', 
						'%s', '%s', '%s', '%s', '%s', 
						'%s', '%s', '%s','%s', '%s',
						'%s','%s','%d', '%s', '%s','%s','%d'
					)
			);
			if($query_wp_dataPost){
				/*create postmeta*/
				/*get post_id từ guid*/
				//$guid = "http://sq.dusted.com.au/wp-content/uploads/2019/01/".$name_image;
				$guid = "http://sq.dusted.com.au/wp-content/uploads/".$current_time_img.$name_image;
				$get_PostQuiz = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '". $name_image."' and comment_status='open' and post_parent='".$parrentId."' and menu_order='0' and guid='".$guid."' ");
				if(!$get_PostQuiz) {
					echo json_encode([
						'signal' => 2,
						'message' => 'create question flase'
					]);
					exit();
				}
				$postId = $get_PostQuiz[0]->ID;
				$table_name_postmeta = $wpdb->prefix.'postmeta';
				$dataPostMetaImageQuestion = array(
					"post_id" => $postId,
					"meta_key" => "_wp_attached_file",
					"meta_value" => $current_time_img.$name_image
				);
				$query_wp_dataPostMetaImageQuestion = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestion,
					array(
						'%d', '%s', '%s'
					)
				);
				if($query_wp_dataPostMetaImageQuestion) {
					$getCountdImgQuestion = $wpdb->get_results( "SELECT * FROM ". $table_name_postmeta ." WHERE post_id = '".$parrentId."' and meta_key='image_question' ");
					if($getCountdImgQuestion){
						$cImgQuestion = $getCountdImgQuestion[0]->meta_value;
						$countImgQuestion = $cImgQuestion + 1;
						$dataPostMetaImageQuestionNew = array(
							"post_id" => $parrentId,
							"meta_key" => "image_question_".$cImgQuestion."_image_question",
							"meta_value" => $postId
						);
						$query_wp_dataPostMetaImageQuestionNew = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestionNew,
							array(
								'%s', '%s', '%d'
							)
						);
						if($query_wp_dataPostMetaImageQuestionNew){
							$dataImgQuestion = $wpdb->update( 
								$table_name_postmeta, 
								array( 
									'meta_value' => $countImgQuestion
								), 
								array('post_id' => $parrentId, 'meta_key' => 'image_question'), 
								array( 
									'%d'
								), 
								array('%s', '%s') 
							);
							if($dataImgQuestion){
								echo json_encode([
									'signal' => 1,
									'message' => 'create question success'
								]);
								exit();
							}else{
								echo json_encode([
									'signal' => 2,
									'message' => 'update image_question false'
								]);
								exit();
							}
						}else{
							echo json_encode([
								'signal' => 2,
								'message' => 'insert new image_question false'
							]);
							exit();
						}
					}else{
						$countImgQuestion = 0;
						$dataPostMetaImageQuestionNewFirst = array(
							"post_id" => $parrentId,
							"meta_key" => "image_question_".$countImgQuestion."_image_question",
							"meta_value" => $postId
						);
						$query_wp_dataPostMetaImageQuestionNewFirst = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestionNewFirst,
							array(
								'%s', '%s', '%d'
							)
						);
						if($query_wp_dataPostMetaImageQuestionNewFirst) {
							$dataPostMetaImageQuestionFirst = array(
								"post_id" => $parrentId,
								"meta_key" => "image_question",
								"meta_value" => 1
							);
							$query_wp_dataPostMetaImageQuestionFirst = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestionFirst,
								array(
									'%d', '%s', '%d'
								)
							);
							if($query_wp_dataPostMetaImageQuestionFirst){
								echo json_encode([
									'signal' => 1,
									'message' => 'create question success'
								]);
								exit();
							}else{
								echo json_encode([
									'signal' => 2,
									'message' => 'insert image_question false'
								]);
								exit();
							}
						}else{
							echo json_encode([
								'signal' => 2,
								'message' => 'insert _image_question false'
							]);
							exit();
						}
					}
					//add image_question
					/*
					$value_image_question = get_field( 'image_question', $postId);
					$value_img = "" ;
					if($value_image_question){
						$value_img = $value_image_question;
					}else{
						$value_img = 1;
					}
					
					$dataPostMetaImageQuestionNew = array(
						"post_id" => $postId,
						"meta_key" => "image_question",
						"meta_value" => $value_img
					);
					$query_wp_dataPostMetaImageQuestionNew = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestionNew,
						array(
							'%d', '%s', '%d'
						)
					);
					if($query_wp_dataPostMetaImageQuestionNew) {
						//add _image_question
						$value = get_field( '_image_question', $postId);
						if(empty($value)){
							$value = "";
						}
						$dataPostMetaImageQuestionNewImg = array(
							"post_id" => $postId,
							"meta_key" => "_image_question",
							"meta_value" => $value
						);
						$query_wp_dataPostMetaImageQuestionNewImg = $wpdb->insert($table_name_postmeta , $dataPostMetaImageQuestionNewImg,
							array(
								'%d', '%s', '%s'
							)
						);
						if($query_wp_dataPostMetaImageQuestionNewImg) {
							echo json_encode([
								'signal' => 1,
								'message' => 'create question success'
							]);
							exit();
						}else{
							echo json_encode([
								'signal' => 2,
								'message' => 'insert _image_question false'
							]);
							exit();
						}
					}else{
						echo json_encode([
								'signal' => 2,
								'message' => 'insert image_question false'
							]);
							exit();
					}
					*/
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'insert _wp_attached_file false'
					]);
					exit();
				}
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'create question post flase'
				]);
				exit();
			}
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'create question master flase'
			]);
			exit();
		}
	}
	
	
	/*editQuestionByQuestionId*/
	public function duseted_editQuestionByQuestionId(){
		global $json_api, $wpdb;
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$quizId = $json_api->query->quiz_id;
		$questionId = $json_api->query->questionId;
		$username = $json_api->query->username;
		$question_title = $json_api->query->question_title;
		//$points = $json_api->query->points;
		$question_question = $json_api->query->question_question;
		$answer_type = $json_api->query->answer_type;
		$answer_question = $json_api->query->answer_question;
		$url_image_old =  $json_api->query->url_image_old;
		$token =  $json_api->query->token;
		$image =  $_FILES['image'];
		//var_dump($image['type']);die;
		//set point default = 5;
		$points = "5";
		
		$checktoken = self::dusted_checkToken($username, $token);	
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		$type_image = $image['type'];
		if(empty($quizId) || empty($question_title) || empty($points)||empty($question_question)||empty($answer_type)||empty($answer_question) || empty($token) || empty($username) || empty($image) || empty($questionId)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		/*check quizId*/
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE id='".$quizId."' ");
		if(!$get_ProQuizMaster){
			echo json_encode([
				'signal' => 2,
				'message' => 'quiz_id invalid'
			]);
			exit();
		}
		//check questionId
		$table_name_quiz_question = $wpdb->prefix.'wp_pro_quiz_question';
		$get_Quiz_question = $wpdb->get_results("SELECT * FROM ".$table_name_quiz_question." WHERE id='".$questionId."' ");
		if(!$get_Quiz_question){
			echo json_encode([
				'signal' => 2,
				'message' => 'questionId does not exist'
			]);
			exit();
		}
		
		if(!in_array($type_image, ["image/jpeg","image/jpg","image/png"])){
			echo json_encode([
				'signal' => 2,
				'message' => 'invalid image format please use png, jpg, jpeg'
			]);
			exit();
		}
		$current_month = date('m');
		$current_year = date("Y");
		$current_time_img = $current_year."/".$current_month."/";
		//check name image already exist
		$name_image = $image['name'];
		$table_postmeta = $wpdb->prefix.'postmeta';
		//$name_image = "2019/01/".$name_image;
		$name_image_new = "http://sq.dusted.com.au/wp-content/uploads/".$current_time_img.$name_image;
		if($url_image_old == $name_image_new){
			$answer_question = json_decode(stripslashes($answer_question));
			$Data_answer_question = [];
			foreach($answer_question as $answers){
				$data_answer = [
					'_answer' => $answers->answer,
					'_points' => $points,
					'_correct' => $answers->correct,
				];
				array_push($Data_answer_question, $data_answer);
			}
			$Data_answer_question = self::createAnswerData($Data_answer_question);
			/*update Question*/
			$dataNewQuestion = $wpdb->update( 
				$table_name_quiz_question, 
				array( 
					'title' => $question_title,
					'points' => $points,
					'question' => $question_question,
					'answer_type' => $answer_type,
					'answer_data' => $Data_answer_question,
					'disable_correct' => (int)(false)
				), 
				array('id' => $questionId), 
				array( 
					'%s', '%d', '%s','%s','%s','%d' 
				), 
				array('%d') 
			);
		    $resQuestion = [
				"quiz_id" => $quizId,
				"questionId" => $questionId,
				"title" => $question_title,
				"points" => $points,
				"question" => $question_question,
				"answer_type" => $answer_type,
				"answer_data" => self::dusted_getAnswer($Data_answer_question),
				"image_question" => $url_image_old
			];
		    echo json_encode([
				'signal' => 1,
				'message' => 'edit question success',
				'data' => $resQuestion
			]);
			exit();		
		}else{
			$tmp_image = $image['tmp_name'];
			$name_image = $image['name'];
			$error_image = $image['error'];
			if($error_image > 0) {
				echo json_encode([
					'signal' => 2,
					'message' => 'upload file image error'
				]);
				exit();
			}else{
				// Upload file
				$domain = 'http://sq.dusted.com.au/wp-content/uploads/'.$current_time_img;
				if ( ! function_exists( 'wp_handle_upload' ) ) {
					require_once( ABSPATH . 'wp-admin/includes/file.php' );
				}
				$upload_overrides = array( 'test_form' => false );
				//if(!wp_handle_upload($image, $upload_overrides, '"'.$current_year."/".$current_month.'"')){
				if(!wp_handle_upload($image, $upload_overrides, $current_year."/".$current_month)){
					echo json_encode([
						'signal' => 2,
						'message' => 'upload file image error'
					]);
					exit();
				}
			}
			$answer_question = json_decode(stripslashes($answer_question));
			$Data_answer_question = [];
			foreach($answer_question as $answers){
				$data_answer = [
					'_answer' => $answers->answer,
					'_points' => $points,
					'_correct' => $answers->correct,
				];
				array_push($Data_answer_question, $data_answer);
			}
			$Data_answer_question =  self::createAnswerData($Data_answer_question);
			/*update Question*/
			$dataNewQuestion = $wpdb->update( 
				$table_name_quiz_question, 
				array( 
					'title' => $question_title,
					'points' => $points,
					'question' => $question_question,
					'answer_type' => $answer_type,
					'answer_data' => $Data_answer_question,
					'disable_correct' => (int)(false)
				), 
				array('id' => $questionId), 
				array( 
					'%s', '%d', '%s','%s','%s','%d' 
				), 
				array('%d') 
			);  
			//var_dump($dataNewQuestion);die;
			if($dataNewQuestion){
				//update image , update 
				//get Post by url_image_old.
				$table_name_posts = $wpdb->prefix.'posts';
				$dataUpdateImagePost = $wpdb->update( 
						$table_name_posts, 
					array( 
						'post_title' => $name_image,
						'post_excerpt' => $name_image,
						'post_name' => $name_image,
						'guid' => $name_image_new,
						'post_mime_type' => $type_image
					), 
					array('guid' => $url_image_old), 
					array( 
						'%s', '%s', '%s','%s','%s'
					), 
					array('%s') 
				);
				if($dataUpdateImagePost){
					//get postId 
					$get_PostImage = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '". $name_image."' and comment_status='open' and  post_status='publish' and guid = '". $name_image_new."' ");
					//get parentId By QuizName (table post)
					$post_id = $get_PostImage[0]->ID;
				
					//update image postmeta
					$dataUpdateImagePostMeta = $wpdb->update( 
							$table_postmeta, 
						array( 
							//'meta_value' => '2019/01/'.$name_image
							'meta_value' => $current_time_img.$name_image
						), 
						array('post_id' => $post_id, 'meta_key'=>'_wp_attached_file'), 
						array( 
							'%s'
						), 
						array('%s', '%s') 
					);
					if($dataUpdateImagePostMeta){
						$resQuestion = [
							"quiz_id" => $quizId,
							"questionId" => $questionId,
							"title" => $question_title,
							"points" => $points,
							"question" => $question_question,
							"answer_type" => $answer_type,
							"answer_data" => self::dusted_getAnswer($Data_answer_question),
							"image_question" => $name_image_new
						];
						echo json_encode([
							'signal' => 1,
							'message' => 'edit question success',
							'data' => $resQuestion
						]);
						exit();
					}
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'edit question image false'
					]);
					exit();
				}
			}else{
				//var_dump($get_Quiz_question[0]->title,$question_title);die;
				if($get_Quiz_question[0]->title == $question_title && $get_Quiz_question[0]->points == $points && $get_Quiz_question[0]->question == $question_question
					&& $get_Quiz_question[0]->answer_type == $answer_type && $get_Quiz_question[0]->answer_data == $Data_answer_question && $get_Quiz_question[0]->disable_correct == (int)(false)
				){
					//update image , update 
					//get Post by url_image_old.
					$table_name_posts = $wpdb->prefix.'posts';
					$dataUpdateImagePost = $wpdb->update( 
							$table_name_posts, 
						array( 
							'post_title' => $name_image,
							'post_excerpt' => $name_image,
							'post_name' => $name_image,
							'guid' => $name_image_new,
							'post_mime_type' => $type_image
						), 
						array('guid' => $url_image_old), 
						array( 
							'%s', '%s', '%s','%s','%s'
						), 
						array('%s') 
					);
					if($dataUpdateImagePost){
						//get postId 
						$get_PostImage = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '". $name_image."' and comment_status='open' and  post_status='publish' and guid = '". $name_image_new."' ");
						//get parentId By QuizName (table post)
						$post_id = $get_PostImage[0]->ID;
						//update image postmeta
						$dataUpdateImagePostMeta = $wpdb->update( 
								$table_postmeta, 
							array( 
								//'meta_value' => '2019/01/'.$name_image
								'meta_value' => $current_time_img.$name_image
							), 
							array('post_id' => $post_id, 'meta_key'=>'_wp_attached_file'), 
							array( 
								'%s'
							), 
							array('%s', '%s') 
						);
						if($dataUpdateImagePostMeta){
							$resQuestion = [
								"quiz_id" => $quizId,
								"questionId" => $questionId,
								"title" => $question_title,
								"points" => $points,
								"question" => $question_question,
								"answer_type" => $answer_type,
								"answer_data" => self::dusted_getAnswer($Data_answer_question),
								"image_question" => $name_image_new
							];
							echo json_encode([
								'signal' => 1,
								'message' => 'edit question success',
								'data' => $resQuestion
							]);
							exit();
						}
					}else{
						echo json_encode([
							'signal' => 2,
							'message' => 'edit question image false'
						]);
						exit();
					}
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'edit question false'
					]);
					exit();
				}
			}
		}
	}
	
	
	static function dusted_getAnswer($data) {
		$dataAnswer = [];
		$answers = unserialize($data);
		foreach($answers as $answer){
			if(!empty($answer->getAnswer())){
				$resAnswer = [
					'answer' => $answer->getAnswer(),
					//'points' => $answer->getPoints(),
					'correct' => $answer->isCorrect()
				];
				array_push($dataAnswer, $resAnswer);
			}
		}
		return $dataAnswer;
	}
	
	//Static quiz_id get title quiz
	//title quiz -> get ParentId
	//parentId->get all image
	static function dusted_getAllImageQuestion($quiz_id){
		global $json_api, $wpdb;
		$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
		$table_name_posts = $wpdb->prefix.'posts';
		$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE id='".$quiz_id."' ");
		$nameQuiz = $get_ProQuizMaster[0]->name;
		$get_PostQuiz = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '".$nameQuiz."' and comment_status='open' and post_parent='0' and menu_order='0' and  post_type='sfwd-quiz' ");
		//get parentId By QuizName (table post)
		$parrentId = $get_PostQuiz[0]->ID;
		//var_dump($get_PostQuiz);die;
		$listImage = [];
		$get_PostQuiz = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE  post_parent='".$parrentId."' and menu_order='0' and (post_mime_type='image/jpeg' OR post_mime_type='image/jpg' OR post_mime_type='image/png')");
		for($i=0; $i<count($get_PostQuiz); $i++){
			array_push($listImage, $get_PostQuiz[$i]->guid);
		}
		//var_dump(count($listImage));die;
		return $listImage;
	}
	
	//getAll Question By Quiz
	public function dusted_getAllQuestionByQuiz(){
		global $json_api, $wpdb;
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$quiz_id = $json_api->query->quiz_id;
		$username =  $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($quiz_id) ||empty($token) || empty($username)){
			echo json_encode([
				'signal' => 0,
				'message'=>'require params'
			]);
			exit();
		}
		//var_dump($dataImage);die;
		$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE quiz_id = '".$quiz_id."' " );
		if(empty($get_dataPost)){
			echo json_encode([
				'signal' => 0,
				'message' => 'quiz_id invalid'
			]);
			exit();
		}
		//Get ListImage
		$dataImage = self::dusted_getAllImageQuestion($quiz_id);
		//var_dump($dataImage);die;
		$dataQuestion = [];
		foreach($get_dataPost as $key => $value){
			$resQuestion = [
				"quiz_id" => $value->quiz_id,
				"id_question" => $value->id,
				"title" => $value->title,
				"points" => $value->points,
				"question" => $value->title,
				"answer_type" => $value->answer_type,
				"answer_data" => $value->answer_data,
				"category_id" => $value->category_id
			];
			array_push($dataQuestion, $resQuestion);
		}
		if(count($dataQuestion)>0) {
			if(count($dataImage) < 0){
				for($i=0; $i<count($dataQuestion); $i++){
					$dataQuestion[$i]["image_question"] = '';
				}
			}else{
				if(count($dataQuestion) >= count($dataImage)){
					for($i=0; $i<count($dataQuestion); $i++){
						$dataAnswer = self::dusted_getAnswer($dataQuestion[$i]["answer_data"]);
						$dataQuestion[$i]["answer_data"] = $dataAnswer;
						for($m=0; $m<=count($dataImage); $m++){
							$dataQuestion[$m]["image_question"] = $dataImage[$m];
						}
						$dataQuestion[$i]["image_question"] = '';
					}
				}else{
					for($i=0; $i<count($dataQuestion); $i++){
						$dataAnswer = self::dusted_getAnswer($dataQuestion[$i]["answer_data"]);
						$dataQuestion[$i]["answer_data"] = $dataAnswer;
						$dataQuestion[$i]["image_question"] = $dataImage[$i];
					}
				}
			}
			echo json_encode([
				'signal' => 1,
				'message' => 'get list question by quiz_id success',
				'dataQuestion' => $dataQuestion
			]);
			exit();
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'get list question by quiz_id false'
			]);
			exit();
		}
	}

	static function sortLearDashByQuizId($quiz_id,$get_UserMeta){
		for($h=0; $h<count($get_UserMeta); $h++){
			$sumPointUser = 0;
			$dataUser = json_decode($get_UserMeta[$h]->meta_value);
			//var_dump($dataUser);die;
			for($k=0; $k<count($dataUser); $k++){
				if($quiz_id == $dataUser[$k]->quiz_id) {	
					$get_UserMeta[$h]->sumPoint = $dataUser[$k]->total_point;
				}
			}
		}
		$sophantu = count($get_UserMeta);
		//Sắp xếp mảng
		for ($i = 0; $i < ($sophantu - 1); $i++)
		{
			for ($j = $i + 1; $j < $sophantu; $j++)
			{
				if ($get_UserMeta[$i]->sumPoint < $get_UserMeta[$j]->sumPoint)
				{
					// hoán vị
					$tmp = $get_UserMeta[$j];
					$get_UserMeta[$j] = $get_UserMeta[$i];
					$get_UserMeta[$i] = $tmp;
				}
			}
		}
		return $get_UserMeta;
		
	}
	public function dusted_LearnDashByQuizId(){
		global $json_api, $wpdb;
		$quiz_id = $json_api->query->quiz_id;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		if(empty($quiz_id) || empty($token) || empty($username)){
			echo json_encode([
				'signal'=>0,
				'message'=>'require params'
			]);
			exit();
		}
		//var_dump($quiz_id,"ahihi");die;
		
		$table_usermeta = $wpdb->prefix.'usermeta';	
		$table_user = $wpdb->prefix.'users';	
		$listDataUser = [];
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$metaKeyPoint = "point_quiz_user";
		$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE meta_key ='".$metaKeyPoint."' " );
		//var_dump($get_UserMeta);die;
		$dataLearDash = [];
		if(!empty($get_UserMeta)){
			$dataSort = self::sortLearDashByQuizId($quiz_id, $get_UserMeta);
			//var_dump($dataSort);die;
			if($dataSort){
				foreach( $dataSort as $UserMeta ){
					//getAvatarUser
					$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = ' ".$UserMeta->user_id." ' and meta_key = 'avatar_user' "  );
					//getUsername By userID
					$get_users = $wpdb->get_results( "SELECT * FROM ". $table_user ." WHERE ID = ' ".$UserMeta->user_id." ' "  );
					//var_dump($get_usermeta, $get_users);die;
					if(count($get_usermetaAvatar) == 0){
						//get data point_quiz_user by userID
						$get_usermetaPointQuiz = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = ' ".$UserMeta->user_id." ' and meta_key = 'point_quiz_user' "  );
						//var_dump($get_usermetaPointQuiz);die;
						//$dataMetaValueUser = json_decode()
						if(empty($get_usermetaPointQuiz)) {
							$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE quiz_id = '".$quiz_id."' " );
							if(empty($get_dataPost)) {
								$dataUser = [
									'quiz_id' => $quiz_id,
									'username' => $get_users[0]->user_nicename,
									'avatar' => '',
									'number_answerTrue' => 0,
									'time_spent' => 0,
									'current_question' =>0,
									'total_question' => 0,
									'total_point' => $UserMeta->sumPoint
								];
								array_push($dataLearDash, $dataUser );
							}else{
								$dataUser = [
									'quiz_id' => $quiz_id,
									'username' => $get_users[0]->user_nicename,
									'avatar' => '',
									'number_answerTrue' => 0,
									'time_spent' => 0,	
									'current_question' =>0,
									'total_question' => count($get_dataPost),
									'total_point' => $UserMeta->sumPoint
								];
								array_push($dataLearDash, $dataUser );
							}
						}else{
							$dataJsonPointQuiz = json_decode($get_usermetaPointQuiz[0]->meta_value);
							for($i=0; $i<=count($dataJsonPointQuiz); $i++){
								if($dataJsonPointQuiz[$i]->quiz_id == $quiz_id){
									$dataUser = [
										'quiz_id' => $quiz_id,
										'username' => $get_users[0]->user_nicename,
										'avatar' => '',
										'number_answerTrue' =>$dataJsonPointQuiz[$i]->number_answerTrue,
										'time_spent' =>$dataJsonPointQuiz[$i]->time_spent,
										'current_question' =>$dataJsonPointQuiz[$i]->current_question,
										'total_question' => $dataJsonPointQuiz[$i]->total_question,
										'total_point' => $dataJsonPointQuiz[$i]->total_point
									];
									array_push($dataLearDash, $dataUser );
								}
							}
						}
					}else{
						$get_usermetaPointQuiz = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = ' ".$UserMeta->user_id." ' and meta_key = 'point_quiz_user' "  );
						if(empty($get_usermetaPointQuiz)){
							$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE quiz_id = '".$quiz_id."' " );
							if(empty($get_dataPost)) {
								$dataUser = [
									'quiz_id' => $quiz_id,
									'username' => $get_users[0]->user_nicename,
									'avatar' => $get_usermetaAvatar[0]->meta_value,
									'number_answerTrue' => 0,
									'time_spent' => 0,
									'current_question' =>0,
									'total_question' => 0,
									'total_point' => $UserMeta->sumPoint
								];
								array_push($dataLearDash, $dataUser );
							}else{
								$dataUser = [
									'quiz_id' => $quiz_id,
									'username' => $get_users[0]->user_nicename,
									'avatar' => $get_usermetaAvatar[0]->meta_value,
									'number_answerTrue' => 0,
									'time_spent' => 0,	
									'current_question' =>0,
									'total_question' => count($get_dataPost),
									'total_point' => $UserMeta->sumPoint
								];
								array_push($dataLearDash, $dataUser );
							}
						}else{
							$dataJsonPointQuiz = json_decode($get_usermetaPointQuiz[0]->meta_value);
							for($i=0; $i<=count($dataJsonPointQuiz); $i++){
								if($dataJsonPointQuiz[$i]->quiz_id == $quiz_id){
									$dataUser = [
										'quiz_id' => $quiz_id,
										'username' => $get_users[0]->user_nicename,
										'avatar' => $get_usermetaAvatar[0]->meta_value,
										'number_answerTrue' =>$dataJsonPointQuiz[$i]->number_answerTrue,
										'time_spent' =>$dataJsonPointQuiz[$i]->time_spent,
										'current_question' =>$dataJsonPointQuiz[$i]->current_question,
										'total_question' => $dataJsonPointQuiz[$i]->total_question,
										'total_point' => $dataJsonPointQuiz[$i]->total_point
									];
									array_push($dataLearDash, $dataUser );
								}
							}
						}
					}
				}
				if(count($dataLearDash)>0){
					echo json_encode([
						'signal' => 1,
						'message' => 'get LearnDash success',
						'data' => $dataLearDash
					]);
					exit();
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'get LearnDash false'
					]);
					exit();
				}
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'get sort LearnDash false'
				]);
				exit();
			}
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'get LearnDash false'
			]);
			exit();
		}
	}
	
	
	//public static function sortLearDash(&$arrayToSort, $meta) 
	static function sortLearDash ($get_UserMeta){
		for($h=0; $h<count($get_UserMeta); $h++){
			$sumPointUser = 0;
			$dataUser = json_decode($get_UserMeta[$h]->meta_value);
			//var_dump($dataUser);die;
			for($k=0; $k<count($dataUser); $k++){
				$sumPointUser = $sumPointUser + $dataUser[$k]->total_point;
			}
			$get_UserMeta[$h]->sumPoint = $sumPointUser ;
		}
		$sophantu = count($get_UserMeta);
		//Sắp xếp mảng
		for ($i = 0; $i < ($sophantu - 1); $i++)
		{
			for ($j = $i + 1; $j < $sophantu; $j++)
			{
				if ($get_UserMeta[$i]->sumPoint < $get_UserMeta[$j]->sumPoint)
				{
					// hoán vị
					$tmp = $get_UserMeta[$j];
					$get_UserMeta[$j] = $get_UserMeta[$i];
					$get_UserMeta[$i] = $tmp;
				}
			}
		}
		return $get_UserMeta;
		
	}
	public function dusted_LearnDashAllUser(){
		global $json_api, $wpdb;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		if(empty($token) || empty($username)){
			echo json_encode([
				'signal'=>0,
				'message'=>'require params'
			]);
			exit();
		}
		//var_dump($quiz_id,"ahihi");die;
		
		$table_usermeta = $wpdb->prefix.'usermeta';	
		$table_user = $wpdb->prefix.'users';	
		$listDataUser = [];
		
		$metaKeyPoint = "point_quiz_user";
		$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE meta_key ='".$metaKeyPoint."' " );
		//var_dump($get_UserMeta);die;
		$dataLearDash = [];
		if(!empty($get_UserMeta)){
			$dataSort = self::sortLearDash($get_UserMeta);
			//var_dump($dataSort);die;
			if($dataSort){
				foreach( $dataSort as $UserMeta ){
					//getAvatarUser
					$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = ' ".$UserMeta->user_id." ' and meta_key = 'avatar_user' "  );
					//getUsername By userID
					$get_users = $wpdb->get_results( "SELECT * FROM ". $table_user ." WHERE ID = ' ".$UserMeta->user_id." ' "  );
					//var_dump($get_usermeta, $get_users);die;
					if(count($get_usermetaAvatar) ==0){
						$dataUser = [
							'username' => $get_users[0]->user_nicename,
							'avatar' => '',
							'total_point' => $UserMeta->sumPoint,
							'allQuiz' => json_decode($UserMeta->meta_value)
						];
						array_push($dataLearDash, $dataUser );
					}else{
						$dataUser = [
							'username' => $get_users[0]->user_nicename,
							'avatar' => $get_usermetaAvatar[0]->meta_value,
							'total_point' => $UserMeta->sumPoint,
							'allQuiz' => json_decode($UserMeta->meta_value)
						];
						array_push($dataLearDash, $dataUser );
					}
				}
				if(count($dataLearDash)>0){
					echo json_encode([
						'signal' => 1,
						'message' => 'get LearnDash success',
						'data' => $dataLearDash
					]);
					exit();
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'get LearnDash false'
					]);
					exit();
				}
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'get sort LearnDash false'
				]);
				exit();
			}
		}else{
			echo json_encode([
				'signal' => 2,
				'message' => 'get LearnDash false'
			]);
			exit();
		}
	}
	
	
	//dusted_LearnDash();
	//API aswer user
	public function dusted_checkAnswerUser(){
		global $json_api, $wpdb;
		$quiz_id = $json_api->query->quiz_id;
		$username = $json_api->query->username;
		//$table_usermeta = $wpdb->prefix.'usermeta';
		$dataAnswerUser = $json_api->query->dataAnswerUser;
		$current_question = $json_api->query->current_question;
		$time_spent = $json_api->query->time_spent;
		//var_dump("xinchao");die;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		
		if(empty($username) || empty($dataAnswerUser) || empty($token) || empty($time_spent) || empty($current_question)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		
		$answer_question = json_decode(stripslashes($dataAnswerUser));
		//$current_question = $answer_question[count($answer_question )-1]->question_id;
		//$current_question = count($answer_question);
		//var_dump(count($answer_question ));die;
		
		if(empty($quiz_id) || empty($username) || empty($dataAnswerUser)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		
		$user = get_userdatabylogin( $username );
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$sumPoint = 0;
		$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE quiz_id = '".$quiz_id."' " );
		$dataQuestion = [];
		foreach($get_dataPost as $key => $value){
			$resQuestion = [
				"quiz_id" => $value->quiz_id,
				"id_question" => $value->id,
				"title" => $value->title,
				"points" => $value->points,
				"question" => $value->title,
				"answer_type" => $value->answer_type,
				"answer_data" => $value->answer_data,
				"category_id" => $value->category_id
			];
			array_push($dataQuestion, $resQuestion);
		}
		if(count($dataQuestion)>0) {
			for($i=0; $i<count($dataQuestion); $i++){
				$dataAnswer = self::dusted_getAnswer($dataQuestion[$i]["answer_data"]);
				$dataQuestion[$i]["answer_data"] = $dataAnswer;
			}
		}
		//var_dump($dataQuestion, $answer_question);die;
		//number question true
		$number_answerTrue = 0;
		//var_dump(($dataQuestion), ($answer_question));die;
		if(count($dataQuestion) >= count($answer_question)){
			for($i=0; $i<count($dataQuestion); $i++){
				for($j=0; $j<count($answer_question); $j++){
					//var_dump($answer_question[$j]->quiz_id == $dataQuestion[$i]['quiz_id']);die;
					//var_dump(settype($answer_question[2]->answer_data->correct,boolean));die;
					if($dataQuestion[$i]['quiz_id'] == $answer_question[$j]->quiz_id && 
					$dataQuestion[$i]['id_question'] == $answer_question[$j]->question_id){
						//var_dump(count($dataQuestion[1]['answer_data']));die;
						//var_dump($dataQuestion[$i]['id_question'] , $answer_question[$j]->question_id, $dataQuestion[$i]['quiz_id'] ,  $answer_question[$j]->quiz_id);die;
						if(count($dataQuestion[1]['answer_data']) > 0){
							//$correct_dash = $answer_question[$j]->answer_data->correct;		
							$correct_dash = $answer_question[$j]->answer_data;		
							for($k=0; $k<count($dataQuestion[$i]['answer_data']); $k++){
								/////var_dump($correct_dash , "ahihi");die;
								if($correct_dash === "bool(true)"){
									$correct_dash = true;
								}elseif($correct_dash === "bool(false)"){
									$correct_dash = false;
								}
								//var_dump($correct_dash);die;
								if( $dataQuestion[$i]['answer_data'][$k]['answer'] == $answer_question[$j]->answer_data->answer &&
								  $correct_dash == $dataQuestion[$i]['answer_data'][$k]['correct']
								){
									//var_dump($dataQuestion[$i]['points']);
									$sumPoint = $sumPoint + $dataQuestion[$i]['points'];
									$number_answerTrue = $number_answerTrue + 1;
								}
							}
						}
					}else{
						//var_dump($dataQuestion[$i]['id_question'] , $answer_question[$j]->question_id, $dataQuestion[$i]['quiz_id'] ,  $answer_question[$j]->quiz_id);die;
					}
				}
			}
		}
		//var_dump($sumPoint);die;
		//die;
		$dataAnswerUser = [
			"quiz_id" => $quiz_id,
			"username" => $username,
			"total_point" => $sumPoint,
			"number_answerTrue" => $number_answerTrue,
			"current_question" => $current_question,
			"total_question" => count($dataQuestion)
		];
		//var_dump($dataAnswerUser);die;
		
		//Thực hiện add vào bảng toplist
		$userID = $user->data->ID;
		$table_toplist = $wpdb->prefix."wp_pro_quiz_toplist";
		$get_UserTopList = $wpdb->get_results( "SELECT * FROM ". $table_toplist ." WHERE quiz_id ='".$quiz_id."' and user_id='".$userID."' ");
		if($get_UserTopList){
			$dataTopList = $wpdb->update( 
				$table_toplist, 
				array( 
					'date' => strtotime(date('Y-m-d H:i:s')),
					'points' => $sumPoint,
					'result' => $sumPoint
				), 
				array('quiz_id' => $quiz_id, 'user_id' => $userID), 
				array( 
					'%d', '%d', '%d'
				), 
				array('%d', '%d') 
			);
			if(empty($dataTopList)){
				echo json_encode([
					'signal' => 2,
					'message' => 'toplist update false'
				]);
				exit();
			}
		}else{
			$dataTopListNews = array(
				'date' => strtotime(date('Y-m-d H:i:s')),
				"user_id" => $userID,
				"quiz_id" => $quiz_id,
				"name" => $user->data->user_nicename,
				"email" => $user->data->user_email,
				"points" => $sumPoint,
				"result" => $sumPoint
			);
			//var_dump($dataTopListNews);die;
			$query_wp_dataTopListNews = $wpdb->insert($table_toplist , $dataTopListNews,
				array(
					'%s', '%d', '%d', '%s', '%s', '%d','%d'
				)
			);
			if(empty($query_wp_dataTopListNews)){
				echo json_encode([
					'signal' => 2,
					'message' => 'toplist create false'
				]);
				exit();
			}
		}
		
		
		//var_dump($dataAnswerUser);die;
		//Insert vào table metaUser
		$table_usermeta = $wpdb->prefix."usermeta";
		$userID = $user->data->ID;
		//get ra trước nếu chưa có thì create, có updated
		//$metaKeyPoint = "point_quiz_id_".$quiz_id;
		$metaKeyPoint = "point_quiz_user";
		$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE meta_key ='".$metaKeyPoint."' and user_id='".$userID."' ");
		//var_dump($userID, $get_UserMeta);die;
	
		if(empty($get_UserMeta)){
			//var_dump("ahihi");die;
			$dataQuizPoint = [
				[
					"quiz_id" => $quiz_id,
					"total_point"  => $sumPoint,
					"time_spent"  => $time_spent,
					"number_answerTrue" => $number_answerTrue,
					"current_question" => $current_question,
					"total_question" => count($dataQuestion)
				]
			];
			$dataQuizPointMeta = json_encode($dataQuizPoint);
			
			$query_wp_usersmeta = $wpdb->insert($table_usermeta , array(
					"user_id" => $userID,
					"meta_key" => $metaKeyPoint,
					"meta_value" => $dataQuizPointMeta,
				),
				array('%d','%s','%s')
			);
			if($query_wp_usersmeta){
				echo json_encode([
					'signal' => 1,
					'message' => 'check answer success',
					'data' => $dataAnswerUser
				]);
				exit();
			}else{
				echo json_encode([
					'signal' => 2,
					'message'=> 'check answer metaUser insert false'
				]);
				exit();
			}
		}else{
			$dataValueQuiz = json_decode($get_UserMeta[0]->meta_value);
			for($i=0; $i<count($dataValueQuiz); $i++){
				//var_dump($dataValueQuiz[$i] -> quiz_id);
				if($dataValueQuiz[$i] -> quiz_id == $quiz_id){
					if($dataValueQuiz[$i]->total_point == $sumPoint){
						echo json_encode([
							'signal' => 1,
							'message' => 'check answer success',
							'data' => $dataAnswerUser
						]);
						exit();
					}else{
						$dataValueQuiz[$i]->total_point = $sumPoint;
						$dataValueQuiz[$i]->time_spent = $time_spent;
						$dataValueQuiz[$i]->number_answerTrue = $number_answerTrue;
						$dataValueQuiz[$i]->current_question = $current_question;
						$dataValueQuizUpdate = json_encode($dataValueQuiz);
						$dataPointUser = $wpdb->update( 
							$table_usermeta , 
								array( 
									'meta_value' => $dataValueQuizUpdate    //string
								), 
								array('user_id' => $userID , 'meta_key' => $metaKeyPoint), 
								array( 
									'%s' 
								), 
								array( '%s', '%s') 
						);
						if($dataPointUser){
							echo json_encode([
								'signal' => 1,
								'message' => 'check answer success',
								'data' => $dataAnswerUser
							]);
							exit();
						}else{
							echo json_encode([
								'signal' => 2,
								'message'=> 'check answer metaUser updated false'
							]);
							exit();
						}
					}
				}else{
					$newPointQuiz = [
						"quiz_id" => $quiz_id,
						"total_point"  => $sumPoint,
						"time_spent"  => $time_spent,
						"number_answerTrue" => $number_answerTrue,
						"current_question" => $current_question,
						"total_question" => count($dataQuestion)
					];
					array_push($dataValueQuiz, $newPointQuiz);
					$dataValueQuizUpdate = json_encode($dataValueQuiz);
					$dataPointUser = $wpdb->update( 
						$table_usermeta, 
						array( 
							'meta_value' => $dataValueQuizUpdate  //string
						), 
						array('user_id' => $userID , 'meta_key' => $metaKeyPoint), 
							array( 
								'%s' 
							), 
							array( '%s', '%s') 
						);
					if($dataPointUser){
						echo json_encode([
							'signal' => 1,
							'message' => 'check answer success',
							'data' => $dataAnswerUser
						]);
						exit();
					}else{
						echo json_encode([
							'signal' => 2,
							'message'=> 'check answer metaUser updated false'
						]);
						exit();
					}
				}
			}
		}
		
		/*
		$data = json_encode([
				  [
					'quiz_id'=> 1,
					'question_id' => 1,
					'title' => 'Question : 1',
					'answer_data' => [ 
						'answer' => 5,
						'correct' => "bool(true)"
					]
				  ],
				  [
					'quiz_id'=> 1,
					'question_id' => 2,
					'title' => 'Question : 2',
					'answer_data' => [ 
						'answer' => 10,
						'correct' => "bool(true)"
					]
				  ],
				  [
					'quiz_id'=> 1,
					'question_id' => 1,
					'title' => 'Question : 3',
					'answer_data' => [ 
						'answer' => 'first answer',
						'correct' => "bool(true)"
					]
				  ]
				]);
		echo $data;die;
		*/
	}
	
	
	
	//API detail Quiz User By User
	public function detailQuizUser(){
		global $json_api, $wpdb;
		$quiz_id = $json_api->query->quiz_id;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($quiz_id) || empty($username) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		$userID = $user->data->ID;
		$table_usermeta = $wpdb->prefix."usermeta";
		$metaKeyPoint = "point_quiz_user";
		$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE meta_key ='".$metaKeyPoint."' and user_id='".$userID."' ");
		if(empty($get_UserMeta)){
			echo json_encode([
				'signal' => 2,
				'message' => 'user has not played the quiz'
			]);
			exit();
		}else{
			$dataValueQuiz = json_decode($get_UserMeta[0]->meta_value);
			for($i=0; $i<count($dataValueQuiz); $i++){
				if($dataValueQuiz[$i]->quiz_id == $quiz_id){
					echo json_encode([
						'signal' => 1,
						'message' => 'success',
						'data' => $dataValueQuiz[$i]
					]);
					exit();
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'user has not played the quiz'
					]);
					exit();
				}
			}
		}
	}
	
	//API detail Quiz By quizId
	public function detailQuizByQuizId(){
		global $json_api, $wpdb;
		$quizId = $json_api->query->quiz_id;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($quizId) || empty($username) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		$userID = $user->data->ID;		
		$table_name_posts = $wpdb->prefix."posts";

		//var_dump($quiz_id);die;
		$nameQuiz = self :: dusted_getNameByQuizId($quizId);
		if(empty($nameQuiz)){
			echo json_encode([
				'signal'=> 2,
				'message'=> 'quiz_id invalid'
			]);
			exit();
		}
		$get_PostQuiz = $wpdb->get_results( "SELECT * FROM ".$table_name_posts."  WHERE post_title = '". $nameQuiz."' and comment_status='open' and post_parent='0' and menu_order='0' and post_type='sfwd-quiz' ");
		$parrentId = $get_PostQuiz[0]->ID;
		//var_dump($parrentId);die;
		if(empty($parrentId)){
			echo json_encode([
				'signal'=> 2,
				'message'=> 'postId invalid'
			]);
			exit();
		}
		$table_name_postmeta = $wpdb->prefix."postmeta";
		$query_wp_dataPostMetaLat = $wpdb->get_results( "SELECT * FROM ". $table_name_postmeta ." WHERE post_id = '".$parrentId."' and meta_key='lat' ");		
		if(empty($query_wp_dataPostMetaLat)){
			echo json_encode([
				'signal' => 2,
				'message' => 'get lat width quiz_id invalid'
			]);
			exit();
		}
		$query_wp_dataPostMetaLong = $wpdb->get_results( "SELECT * FROM ". $table_name_postmeta ." WHERE post_id = '".$parrentId."' and meta_key='long' ");
		if(empty($query_wp_dataPostMetaLong)){
			echo json_encode([
				'signal' => 2,
				'message' => 'get long width quiz_id invalid'
			]);
			exit();
		}
		$post_author = $get_PostQuiz[0]->post_author;
		$table_name_users = $wpdb->prefix."users";
		$query_wp_dataUser = $wpdb->get_results( "SELECT * FROM ". $table_name_users ." WHERE ID = '".$post_author."'");
		//var_dump($query_wp_dataUser[0]->user_nicename);die;
		if(empty($query_wp_dataUser)){
			echo json_encode([
				'signal' => 2,
				'message' => 'user quiz invalid'
			]);
			exit();
		}
		$table_usermeta = $wpdb->prefix."usermeta";
		$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$post_author."' and meta_key = 'avatar_user' "  );
		
		if(empty($get_usermetaAvatar)){
			$avatarUser = "";
		}
		$avatarUser = $get_usermetaAvatar[0]->meta_value;
		$userCreateQuiz = [
			'username' => $query_wp_dataUser[0]->user_nicename,
			'avatar' => $avatarUser
		];
		//Tinh  Average Time (nó là tổng số time của tất cả các user đã chơi quizz này/chia cho tổng số người chơi)
		$Average_Time = "";
		$total_Time = "";
		$countUser = "";
		$get_usermeta = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE meta_key = 'point_quiz_user' " );
		for($i=0; $i<=count($get_usermeta); $i++){
			$item_answerQuiz = json_decode($get_usermeta[$i]->meta_value);
			//var_dump($item_answerQuiz);die;
			for($j=0; $j<=count($item_answerQuiz); $j++){
				//var_dump($item_answerQuiz[$j]->quiz_id);die;
				if($item_answerQuiz[$j]->quiz_id == $quizId){
					//$Average_Time = $Average_Time->diff($item_answerQuiz[$j]->time_spent);
					$time_play_quiz = substr($item_answerQuiz[$j]->time_spent,2,strlen($item_answerQuiz[$j]->time_spent)-4);
					$total_Time = $total_Time + strtotime($time_play_quiz);
					$countUser = $countUser+1;
				}
			}
		}
		if($countUser > 0){
			$Average_Time = $total_Time/$countUser;
		}
		//var_dump($Average_Time);die;
		
		//check user da answer question chua? if answer response total question
		$get_usermetaQuestion = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$post_author."' and meta_key = 'point_quiz_user' " );
		//$get_usermetaQuestion = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = 1 and meta_key = 'point_quiz_user' " );
		//$dataMetaQuestionUser = json_decode($get_usermetaQuestion[0]->meta_value);
		if(empty($get_usermetaQuestion)){
			//get tatal question by quiz_id
			$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
			$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE quiz_id = '".$quizId."' " );
			if(empty($get_dataPost)){
				$resDataDetailQuizByQuizId = [
					'quiz_id' => $quizId,
					'nameQuiz' => $nameQuiz,
					'userCreateQuiz' => $userCreateQuiz,
					'user_completed_question' => 0,
					'time_spent' => 0,
					'total_question' => 0,
					'Average_Time' => $Average_Time,
					'lat' => $query_wp_dataPostMetaLat[0]->meta_value,
					'long' => $query_wp_dataPostMetaLong[0]->meta_value
				];
				echo json_encode([
					'signal' => 1,
					'message' => 'success',
					'data' => $resDataDetailQuizByQuizId
				]);
				exit();
			}else{
				$resDataDetailQuizByQuizId = [
					'quiz_id' => $quizId,
					'nameQuiz' => $nameQuiz,
					'userCreateQuiz' => $userCreateQuiz,
					'time_spent' => 0,
					'user_completed_question' => 0,
					'total_question' => count($get_dataPost),
					'Average_Time' => $Average_Time,
					'lat' => $query_wp_dataPostMetaLat[0]->meta_value,
					'long' => $query_wp_dataPostMetaLong[0]->meta_value
				];
				echo json_encode([
					'signal' => 1,
					'message' => 'success',
					'data' => $resDataDetailQuizByQuizId
				]);
				exit();
			}
		}
		$dataMetaQuestionUser = json_decode($get_usermetaQuestion[0]->meta_value);
		for($i=0; $i<=count($dataMetaQuestionUser); $i++){
			if($dataMetaQuestionUser[$i]->quiz_id == $quizId) {
				$userAnswer = [
					'quiz_id' => $dataMetaQuestionUser[$i]->quiz_id,
					'total_point' => $dataMetaQuestionUser[$i]->total_point,
					'time_spent' => $dataMetaQuestionUser[$i]->time_spent,
					'number_answerTrue' => $dataMetaQuestionUser[$i]->number_answerTrue,
					'current_question' => $dataMetaQuestionUser[$i]->current_question,
					'total_question' => $dataMetaQuestionUser[$i]->total_question
				];
			}
		}
	
		$resDataDetailQuizByQuizId = [
				'quiz_id' => $quizId,
				'nameQuiz' => $nameQuiz,
				'userCreateQuiz' => $userCreateQuiz,
				'user_completed_question' => $userAnswer,
				'Average_Time' => $Average_Time,
				'lat' => $query_wp_dataPostMetaLat[0]->meta_value,
				'long' => $query_wp_dataPostMetaLong[0]->meta_value,
				'total_question' => count($get_dataPost)
		];
		echo json_encode([
			'signal' => 1,
			'message' => 'success',
			'data' => $resDataDetailQuizByQuizId
		]);
		exit();
		
	}
	
	//get Question By Quiz_id
	public function dusted_getQuestion(){
		global $json_api, $wpdb;
		$table_name_question = $wpdb->prefix.'wp_pro_quiz_question';
		$question_id = $json_api->query->question_id;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($question_id) || empty($token) || empty($username)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$get_dataPost = $wpdb->get_results( "SELECT * FROM ". $table_name_question ." WHERE id = '".$question_id."' " );
		if($get_dataPost){
			$resQuestion = [
				"quiz_id" => $get_dataPost[0]->quiz_id,
				"id_question" => $get_dataPost[0]->id,
				"title" => $get_dataPost[0]->title,
				"points" => $get_dataPost[0]->points,
				"question" => $get_dataPost[0]->title,
				"answer_type" => $get_dataPost[0]->answer_type,
				"answer_data" => self::dusted_getAnswer($get_dataPost[0]->answer_data),
				"category_id" => $get_dataPost[0]->category_id
			];
			echo json_encode([
				'signal' => 1,
				'message' => 'get question success',
				'data' => $resQuestion
			]);
			exit();
		}else{
			echo json_encode([
				'signal' => 1,
				'message' => 'get question success',
				'data' => $resQuestion
			]);
			exit();
		}
	}
	
	//API search all Quiz By lat long
	//API search map, params: lat long, username, token
	public function dusted_searchMapBySurbub() {
		global $json_api, $wpdb;
		$table_posts = $wpdb->prefix.'posts';
		$table_postmeta = $wpdb->prefix.'postmeta';
		$username = $json_api->query->username;
		$lat =  $json_api->query->latz;
		$long =  $json_api->query->longz;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($username) || empty($lat) || empty($long) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		$user = get_userdatabylogin( $username );
		$userID = $user->data->ID;
		//var_dump($userID);die;
		//$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_postmeta ." WHERE 
		/*
		$get_UserMeta = $wpdb->get_results("
				Select A.post_id, A.meta_value, A.meta_key
				from wp_postmeta A
				join wp_postmeta B
				on (A.meta_key='lat' or A.meta_key='long') and A.post_id = B.post_id
				GROUP BY A.post_id, A.meta_value, A.meta_key
		");
		*/
		$get_UserMeta = $wpdb->get_results("
				SELECT
					  post_id, C.lat, C.lng, (
						6371 * acos (
						  cos ( radians('". $lat ."') )
						  * cos( radians( C.lat ) )
						  * cos( radians( C.lng ) - radians('". $long ."') )
						  + sin ( radians('". $lat ."') )
						  * sin( radians( C.lat ) )
						)
					  ) AS distance
					FROM(
						Select A.post_id, A.meta_value as lat, B.meta_value as lng
						FROM
						(Select post_id, meta_value, meta_key
						from wp_postmeta
						where (meta_key='lat') and post_id = post_id
						GROUP BY post_id, meta_value, meta_key) A,
						(Select post_id, meta_value, meta_key
						from wp_postmeta
						where (meta_key='long') and post_id = post_id
						GROUP BY post_id, meta_value, meta_key) B
						Where A.post_id = B.post_id
					) C
					HAVING distance < 100
					ORDER BY distance
					LIMIT 0 , 20;
		");
		//var_dump($userID);die;
		if(empty($get_UserMeta)) {
			echo json_encode([
				'signal' => 1,
				'message' => 'quizId does not by width map',
				'data' => []
			]);
			exit();
		}else{
			//get avatar
			$table_usermeta = $wpdb->prefix.'usermeta';	
			$get_usermetaAvatar = $wpdb->get_results( "SELECT * FROM ". $table_usermeta ." WHERE user_id = '".$userID."' and meta_key = 'avatar_user' " );
			//var_dump($get_usermetaAvatar);die;
			if(empty($get_usermetaAvatar)){
				$avatar = "";
			}else{
				$avatar = $get_usermetaAvatar[0]->meta_value;
			}
			//var_dump(count($get_UserMeta));die;
			for($i=0; $i<count($get_UserMeta); $i++){
				$table_name_master = $wpdb->prefix.'wp_pro_quiz_master';
				$table_name_posts = $wpdb->prefix.'posts';
				$get_Postdata = $wpdb->get_results("SELECT * FROM ".$table_name_posts." WHERE ID ='".$get_UserMeta[$i]->post_id."' and post_type='sfwd-quiz' ");
				//var_dump($get_Postdata[0]->post_status);die;
				//$canView = "";
				if($get_Postdata){
					if($get_Postdata[0]->post_status == "publish") {
						//var_dump("vao day");die;
						$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE name='".$get_Postdata[0]->post_title."' ");
						$quiz_id = $get_ProQuizMaster[0]->id;
						//var_dump($quiz_id);die;
						$get_UserMeta[$i]->quiz_id = $quiz_id;
						$get_UserMeta[$i]->nameQuiz = $get_Postdata[0]->post_title;
						$get_UserMeta[$i]->status = "publish";
						$get_UserMeta[$i]->canView  = "true";
						$get_UserMeta[$i]->avatar  = $avatar;
					}else{
						$get_ProQuizMaster = $wpdb->get_results("SELECT * FROM ".$table_name_master." WHERE name='".$get_Postdata[0]->post_title."' ");
						$quiz_id = $get_ProQuizMaster[0]->id;
						//var_dump($quiz_id);die;
						$get_UserMeta[$i]->quiz_id = $quiz_id;
						$get_UserMeta[$i]->nameQuiz = $get_Postdata[0]->post_title;
						$get_UserMeta[$i]->status = "private";
						$get_UserMeta[$i]->avatar  = $avatar;
						//var_dump($get_UserMeta[$i]->status);die;
						if($get_Postdata[0]->post_author == $userID || $get_Postdata[0]->post_author == 1) {
							$get_UserMeta[$i]->canView  = "true";
							//$get_UserMeta[$i]->status = "private";
						}else{
							$get_UserMeta[$i]->canView  = "false";
						}
						//var_dump($get_UserMeta[$i]);die;
					}
				}else{
					unset($get_UserMeta[$i]);
				}
			}
			echo json_encode([
				'signal' => 1,
				'message' => 'search map success',	
				'data' => $get_UserMeta
			]);
			exit();
		}
	}
	
	//API search map, params: post_code
	public function dusted_searchMapByPostCode(){
		global $json_api, $wpdb;
		$table_name_usermeta = $wpdb->prefix.'usermeta';
		$table_posts = $wpdb->prefix.'posts';
		$table_postmeta = $wpdb->prefix.'postmeta';
		$post_code = $json_api->query->post_code;
		$username = $json_api->query->username;
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		if(empty($username) || empty($post_code) || empty($token)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		
		//từ postcode get đc userID
		$get_UserMeta = $wpdb->get_results( "SELECT * FROM ". $table_name_usermeta ." WHERE meta_key ='post_code' and meta_value= '".$post_code."' " );
		if($get_UserMeta){
			$user_id = $get_UserMeta[0]->user_id;
			/*get list quiz*/
			$get_listdata = $wpdb->get_results( "SELECT * FROM ".$table_posts." WHERE post_author='".$user_id."' and comment_status='open' and post_parent='0' and menu_order='0' and  post_status='publish' and post_type='sfwd-quiz' ");
			if($get_listdata){
				$dataListPostId = [];
				for($i=0; $i<count($get_listdata); $i++){
					$dataQuiz = [
						'id' => $get_listdata[$i]->ID,
						'quiz_name'=> $get_listdata[$i]->post_title
					];
					array_push($dataListPostId, $dataQuiz);
				}	
				//var_dump($dataListPostId);die;
				
				if(count($dataListPostId)>0) {
					for($i=0; $i<count($dataListPostId); $i++){
						//var_dump($dataListPostId[$i]['id']);die;
						//Thực hiện get lat long trong postmeta
						$get_PostMeta = $wpdb->get_results( "SELECT * FROM ". $table_postmeta ." WHERE post_id= '".$dataListPostId[$i]['id']."' AND (meta_key='lat' OR meta_key='long') " );
						if(empty($get_PostMeta)){
							$dataListPostId[$i]['lat'] = '';
							$dataListPostId[$i]['long'] = '';
						}else{
							for($j=0; $j<count($get_PostMeta);$j++){
								if($get_PostMeta[$j]->meta_key == 'lat') {
									$dataListPostId[$i]['lat'] = $get_PostMeta[$j]->meta_value;
								}elseif($get_PostMeta[$j]->meta_key == 'long'){
									$dataListPostId[$i]['long'] = $get_PostMeta[$j]->meta_value;
								}
							}
						}
					}
					echo json_encode([
						'signal' => 1,
						'message' => 'get list lat long success',
						'data' => $dataListPostId
					]);
					exit();
				}else{
					echo json_encode([
						'signal' => 2,
						'message' => 'get post_id quiz false'
					]);
					exit();
				}
			}else{
				echo json_encode([
					'signal' => 2,
					'message' => 'user not create quiz'
				]);
				exit();
			}
		}else {
			echo json_encode([
				'signal' => 2,
				'message' => 'post_code not exits'
			]);
			exit();
		}
	}
	
	
	//get list Body
	public function duseted_getListBody() {
		global $json_api, $wpdb;
		$table_name_usermeta = $wpdb->prefix.'usermeta';
		$username = $json_api->query->user_name;
		/*
		$token =  $json_api->query->token;
		$checktoken = self::dusted_checkToken($username, $token);
		if($checktoken['signal'] == 2){
			echo json_encode([
				'signal' => 2,
				'message' => $checktoken['message']
			]);
			exit();
		}
		*/
		
		if(empty($username)){
			echo json_encode([
				'signal' => 0,
				'message' => 'require params'
			]);
			exit();
		}
		/*
		if($username != "admin"){
			echo json_encode([
				'signal' => 0,
				'message' => 'username not value default'
			]);
			exit();
		}*/
		$listDataBody = [
			"Boy" => [
				"Accessories" => [
					"Accessories1" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/01.png",
					"Accessories2" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/02.png",
					"Accessories3" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/03.png",
					"Accessories4" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/04.png",
					"Accessories5" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/05.png",
					"Accessories6" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/06.png",
					"Accessories7" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/07.png",
					"Accessories8" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/08.png",
					"Accessories9" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/09.png",
					"Accessories10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/10.png",
					"Accessories11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Accessories/11.png"
				],
				"Body" => [
					"body1" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Body/01.png",
					"body2" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Body/02.png",
					"body3" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Body/03.png",
					"body4" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Body/04.png"
				],
				"Brows" => [
					"Brows1" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/01.png",
					"Brows2" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/02.png",
					"Brows3" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/03.png",
					"Brows4" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/04.png",
					"Brows5" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/05.png",
					"Brows6" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/06.png",
					"Brows7" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/07.png",
					"Brows8" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/08.png",
					"Brows9" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/09.png",
					"Brows10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/10.png",
					"Brows11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/11.png",
					"Brows12" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/12.png",
					"Brows13" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/13.png",
					"Brows14" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/14.png",
					"Brows15" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/15.png",
					"Brows16" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/16.png",
					"Brows17" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/17.png",
					"Brows18" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/18.png",
					"Brows19" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/19.png",
					"Brows20" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/20.png",
					"Brows21" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/21.png",
					"Brows22" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/22.png",
					"Brows23" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/23.png",
					"Brows24" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/24.png",
					"Brows25" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/25.png",
					"Brows26" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/26.png",
					"Brows27" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/27.png",
					"Brows28" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Brows/28.png"
				],
				"Clothes" => [
					"Clothes1" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/01.png",
					"Clothes2" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/02.png",
					"Clothes3" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/03.png",
					"Clothes4" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/04.png",
					"Clothes5" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/05.png",
					"Clothes6" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/06.png",
					"Clothes7" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/07.png",
					"Clothes8" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/08.png",
					"Clothes9" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Clothes/09.png"
				],
				"Eyes" => [
					"Eyes01" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/01.png",
					"Eyes02" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/02.png",
					"Eyes03" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/03.png",
					"Eyes04" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/04.png",
					"Eyes05" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/05.png",
					"Eyes06" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/06.png",
					"Eyes07" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/07.png",
					"Eyes08" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/08.png",
					"Eyes09" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/09.png",
					"Eyes10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/10.png",
					"Eyes11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/11.png",
					"Eyes12" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/12.png",
					"Eyes13" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/13.png",
					"Eyes14" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/14.png",
					"Eyes15" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/15.png",
					"Eyes16" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/16.png",
					"Eyes17" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/17.png",
					"Eyes18" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/18.png",
					"Eyes19" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/19.png",
					"Eyes20" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/20.png",
					"Eyes21" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Eyes/21.png",
				],
				"Hair" => [
					"Hair01" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/01.png",
					"Hair02" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/02.png",
					"Hair03" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/03.png",
					"Hair04" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/04.png",
					"Hair05" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/05.png",
					"Hair06" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/06.png",
					"Hair07" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/07.png",
					"Hair08" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/08.png",
					"Hair09" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/09.png",
					"Hair10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/10.png",
					"Hair11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/11.png",
					"Hair12" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/12.png",
					"Hair13" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/13.png",
					"Hair14" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/14.png",
					"Hair15" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/15.png",
					"Hair16" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/16.png",
					"Hair17" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/17.png",
					"Hair18" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/18.png",
					"Hair19" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/19.png",
					"Hair20" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/20.png",
					"Hair21" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/21.png",
					"Hair22" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/22.png",
					"Hair23" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/23.png",
					"Hair24" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/24.png",
					"Hair25" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/25.png",
					"Hair26" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/26.png",
					"Hair27" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/27.png",
					"Hair28" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/28.png",
					"Hair29" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/29.png",
					"Hair30" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/30.png",
					"Hair31" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/31.png",
					"Hair32" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/32.png",
					"Hair33" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/33.png",
					"Hair34" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/34.png",
					"Hair35" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/35.png",
					"Hair36" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/36.png",
					"Hair37" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/37.png",
					"Hair38" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Hair/38.png"
				],
				"Mouth" => [
					"Mouth01" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/01.png",
					"Mouth02" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/02.png",
					"Mouth03" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/03.png",
					"Mouth04" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/04.png",
					"Mouth05" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/05.png",
					"Mouth06" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/06.png",
					"Mouth07" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/07.png",
					"Mouth08" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/08.png",
					"Mouth09" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/09.png",
					"Mouth10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/10.png",
					"Mouth11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/11.png",
					"Mouth12" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/12.png",
					"Mouth13" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/13.png",
					"Mouth14" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/14.png",
					"Mouth15" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/15.png",
					"Mouth16" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/16.png",
					"Mouth17" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/17.png",
					"Mouth18" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/18.png",
					"Mouth19" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/19.png",
					"Mouth20" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/20.png",
					"Mouth21" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/21.png",
					"Mouth22" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/22.png",
					"Mouth23" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/23.png",
					"Mouth24" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/24.png",
					"Mouth25" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/25.png",
					"Mouth26" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/26.png",
					"Mouth27" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/27.png",
					"Mouth28" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/28.png",
					"Mouth29" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/29.png",
					"Mouth30" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Mouth/30.png"
				],
				"Nose" => [
					"Nose01" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/01.png",
					"Nose02" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/02.png",
					"Nose03" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/03.png",
					"Nose04" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/04.png",
					"Nose05" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/05.png",
					"Nose06" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/06.png",
					"Nose07" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/07.png",
					"Nose08" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/08.png",
					"Nose09" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/09.png",
					"Nose10" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/10.png",
					"Nose11" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/11.png",
					"Nose12" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/12.png",
					"Nose13" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/13.png",
					"Nose14" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/14.png",
					"Nose15" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/15.png",
					"Nose16" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/16.png",
					"Nose17" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/17.png",
					"Nose18" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/18.png",
					"Nose19" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/19.png",
					"Nose20" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/20.png",
					"Nose21" => "http://sq.dusted.com.au/wp-includes/images/Boys_Assets_Updates/Nose/21.png"
				]
			],
			"Girl" => [
				"Accessories" => [
					"Accessories01" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/01.png",
					"Accessories02" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/02.png",
					"Accessories03" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/03.png",
					"Accessories04" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/04.png",
					"Accessories05" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/05.png",
					"Accessories06" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/06.png",
					"Accessories07" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/07.png",
					"Accessories08" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/08.png",
					"Accessories09" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/09.png",
					"Accessories10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/10.png",
					"Accessories11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/11.png",
					"Accessories12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/12.png",
					"Accessories13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/13.png",
					"Accessories14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/14.png",
					"Accessories15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Accessories/15.png"
				],
				"Body" => [
					"body1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Body/01.png",
					"body2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Body/02.png",
					"body3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Body/03.png",
					"body4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Body/04.png"
				],
				"Brows" => [
					"Brows1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/01.png",
					"Brows2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/02.png",
					"Brows3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/03.png",
					"Brows4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/04.png",
					"Brows5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/05.png",
					"Brows6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/06.png",
					"Brows7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/07.png",
					"Brows8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/08.png",
					"Brows9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/09.png",
					"Brows10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/10.png",
					"Brows11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/11.png",
					"Brows12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/12.png",
					"Brows13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/13.png",
					"Brows14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/14.png",
					"Brows15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/15.png",
					"Brows16" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/16.png",
					"Brows17" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/17.png",
					"Brows18" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/18.png",
					"Brows19" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/19.png",
					"Brows20" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/20.png",
					"Brows21" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/21.png",
					"Brows22" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/22.png",
					"Brows23" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/23.png",
					"Brows24" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/24.png",
					"Brows25" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/25.png",
					"Brows26" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/26.png",
					"Brows27" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/27.png",
					"Brows28" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/28.png",
					"Brows29" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/29.png",
					"Brows30" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Brows/30.png"
				],
				"Clothes" => [
					"Clothes1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/01.png",
					"Clothes2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/02.png",
					"Clothes3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/03.png",
					"Clothes4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/04.png",
					"Clothes5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/05.png",
					"Clothes6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/06.png",
					"Clothes7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/07.png",
					"Clothes8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/08.png",
					"Clothes9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Clothes/09.png"
				],
				"Eyes" => [
					"Eyes1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/01.png",
					"Eyes2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/02.png",
					"Eyes3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/03.png",
					"Eyes4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/04.png",
					"Eyes5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/05.png",
					"Eyes6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/06.png",
					"Eyes7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/07.png",
					"Eyes8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/08.png",
					"Eyes9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/09.png",
					"Eyes10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/10.png",
					"Eyes11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/11.png",
					"Eyes12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/12.png",
					"Eyes13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/13.png",
					"Eyes14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/14.png",
					"Eyes15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/15.png",
					"Eyes16" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/16.png",
					"Eyes17" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/17.png",
					"Eyes18" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/18.png",
					"Eyes19" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/19.png",
					"Eyes20" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/20.png",
					"Eyes21" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/21.png",
					"Eyes22" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/22.png",
					"Eyes23" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/23.png",
					"Eyes24" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/24.png",
					"Eyes25" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Eyes/25.png"
				],
				"Hair" => [
					"Hair1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/01.png",
					"Hair2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/02.png",
					"Hair3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/03.png",
					"Hair4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/04.png",
					"Hair5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/05.png",
					"Hair6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/06.png",
					"Hair7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/07.png",
					"Hair8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/08.png",
					"Hair9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/09.png",
					"Hair10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/10.png",
					"Hair11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/11.png",
					"Hair12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/12.png",
					"Hair13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/13.png",
					"Hair14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/14.png",
					"Hair15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/15.png",
					"Hair16" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/16.png",
					"Hair17" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/17.png",
					"Hair18" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/18.png",
					"Hair19" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/19.png",
					"Hair20" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/20.png",
					"Hair21" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/21.png",
					"Hair22" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/22.png",
					"Hair23" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/23.png",
					"Hair24" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/24.png",
					"Hair25" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/25.png",
					"Hair26" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/26.png",
					"Hair27" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/27.png",
					"Hair28" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/28.png",
					"Hair29" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/29.png",
					"Hair30" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/30.png",
					"Hair31" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/31.png",
					"Hair32" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/32.png",
					"Hair33" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/33.png",
					"Hair34" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/34.png",
					"Hair35" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Hair/35.png"
				],
				"Mouth" => [
					"Mouth1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/01.png",
					"Mouth2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/02.png",
					"Mouth3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/03.png",
					"Mouth4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/04.png",
					"Mouth5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/05.png",
					"Mouth6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/06.png",
					"Mouth7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/07.png",
					"Mouth8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/08.png",
					"Mouth9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/09.png",
					"Mouth10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/10.png",
					"Mouth11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/11.png",
					"Mouth12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/12.png",
					"Mouth13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/13.png",
					"Mouth14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/14.png",
					"Mouth15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/15.png",
					"Mouth16" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/16.png",
					"Mouth17" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/17.png",
					"Mouth18" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/18.png",
					"Mouth19" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/19.png",
					"Mouth20" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/20.png",
					"Mouth21" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/21.png",
					"Mouth22" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/22.png",
					"Mouth23" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/23.png",
					"Mouth24" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/24.png",
					"Mouth25" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/25.png",
					"Mouth26" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/26.png",
					"Mouth27" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/27.png",
					"Mouth28" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/28.png",
					"Mouth29" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/29.png",
					"Mouth30" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/30.png",
					"Mouth31" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/31.png",
					"Mouth32" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/32.png",
					"Mouth33" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/33.png",
					"Mouth34" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/34.png",
					"Mouth35" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/35.png",
					"Mouth36" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/36.png",
					"Mouth37" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Mouth/37.png"
				],
				"Nose" => [
					"Nose1" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/01.png",
					"Nose2" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/02.png",
					"Nose3" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/03.png",
					"Nose4" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/04.png",
					"Nose5" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/05.png",
					"Nose6" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/06.png",
					"Nose7" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/07.png",
					"Nose8" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/08.png",
					"Nose9" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/09.png",
					"Nose10" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/10.png",
					"Nose11" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/11.png",
					"Nose12" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/12.png",
					"Nose13" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/13.png",
					"Nose14" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/14.png",
					"Nose15" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/15.png",
					"Nose16" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/16.png",
					"Nose17" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/17.png",
					"Nose18" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/18.png",
					"Nose19" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/19.png",
					"Nose20" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/20.png",
					"Nose21" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/21.png",
					"Nose22" => "http://sq.dusted.com.au/wp-includes/images/Girls_Assets_Updated/Nose/22.png"
				]
			]
		];
		echo json_encode([
			'signal' => 1,
			'message' => 'get list body success',
			'dataListBody' => $listDataBody
		]);
		exit();
	}
	
	
	
}

?>