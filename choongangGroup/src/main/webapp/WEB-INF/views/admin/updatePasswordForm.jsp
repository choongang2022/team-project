<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
<!-- bootStrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- RSA JS -->
<script src="/js/jsbn.js" type="text/javascript"></script>
<script src="/js/rsa.js" type="text/javascript"></script>
<script src="/js/prng4.js" type="text/javascript"></script>
<script src="/js/rng.js" type="text/javascript"></script>
<!-- This Page JS -->
<script src="/js/adminJS/updatePasswordForm.js" type="text/javascript"></script>

<style type="text/css">
	html, body {
		height: 100%;
	}
	body {
		background-color: rgb(214, 225, 237);
	}
	.container {
		max-width: 420px;
	}
</style>
</head>
<body>
	<main class="container position-absolute top-50 start-50 translate-middle form-signin w-100 m-auto text-center">
		<h1 class="mb-5 fw-bold">비밀번호 변경</h1>
		<div class="form-floating">
			<input type="password" class="form-control bg-light mt-1" id="currentPw" aria-describedby="passwordChkDiv" onfocusout="pwChk()">
			<label for="floatingPassword">현재 비밀번호</label>
			<small id="CchkResult" class="text-muted"></small>
		</div>
		<div class="form-floating">
			<input type="password" class="form-control bg-light mt-3" id="password">
			<label for="floatingPassword">새 비밀번호</label>
		</div>
		<div class="form-floating d-flex flex-column">
			<input type="password" class="form-control bg-light mt-1" id="password2" aria-describedby="passwordChkDiv" onfocusout="pw12Chk()">
			<label for="floatingPassword">새 비밀번호 확인</label>
			<small id="NchkResult" class="text-muted"></small>
			<small id="NchkResult2" class="text-muted"></small>
		</div>
		<button class="w-100 btn btn-lg btn-primary mb-3 mt-3" type="button" onclick="validateEncryptForm();">비밀번호 변경</button>
		<button class="w-100 btn btn-lg btn-primary mb-3 mt-3" type="button" onclick="location.href='/'">메인으로 돌아가기</button>
	</main>
<!-- hidden values -->
<input type="hidden" id="rsaPulbicKeyModulus" value="${publicKeyModulus}">
<input type="hidden" id="rsaPulbicKeyExponent" value="${publicKeyExponent}">
</body>
</html>