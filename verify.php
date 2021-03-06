<?php
/**
	svc verify
	Verify a newly registered user.
*/
function verify() {
	$a = array(
	    'status' => 'system-error'
	);

	// get raw inputs
	$taint_si = isset($_POST['si']) ? $_POST['si'] : 0;
	$taint_tic = isset($_POST['tic']) ? $_POST['tic'] : 0;
	$taint_pword = isset($_POST['pword']) ? $_POST['pword'] : 0;

	// validate inputs
	$si = validateToken($taint_si);
	$tic = validateTic($taint_tic);
	$pword = validatePword($taint_pword);

	// validate parameter set
	if (!$si || !$tic || !$pword) {
		Log::write(LOG_WARNING, 'attempt with invalid parameter set');
		return $a;
	}

	// get db connection
	$conn = getConnection();
	if (!$conn) {
		return $a;
	}

	// get logged-in user
	$result = getUserByToken($conn, $si);
	if (!$result) {
		return $a;
	}

	// get user data
	$row = pg_fetch_array($result, 0, PGSQL_ASSOC);
	$userid = $row['id'];
	$hashpassword = $row['hashpassword'];
	$auth = $row['auth'];
	$hashtic = $row['hashtic'];

	// verify auth
	if (!isUserRegistered($auth)) {
	 	Log::write(LOG_NOTICE, 'attempt by already verified user');
		return $a;
	}

	// verify password
	$boo = verifyPassword($pword, $hashpassword);
	if (!$boo) {
		Log::write(LOG_NOTICE, 'attempt with invalid password');
		return $a;
	}

	// verify tic
	$boo = verifyTic($tic, $hashtic);
	if (!$boo) {
		Log::write(LOG_NOTICE, 'attempt with invalid tic');
		return $a;
	}

	// set new auth
	$auth = DB::$auth_verified;

	// update user record
	$name = 'verify-registration';
	$sql = "update account.user set auth = $1, tmverify = now() where id = $2";
	$params = array($auth, $userid);
	$result = execSql($conn, $name, $sql, $params, true);
	if (!$result) {
		return $a;
	}

	// success
	$a['status'] = 'ok';
	$a['auth'] = $auth;
	return $a;
}
?>
