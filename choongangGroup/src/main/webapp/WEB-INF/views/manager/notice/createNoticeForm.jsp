<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../header.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- bottSTrap CSS only -->
<link
	href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css"
	rel="stylesheet"
	integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi"
	crossorigin="anonymous">
<!-- bootStrap Icons -->
<link rel="stylesheet"
	href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script
	src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js"
	integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3"
	crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css"
	integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A=="
	crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">

<title>SideBar sub menus</title>
</head>
<%
	String context = request.getContextPath();
%>

<body class="" id="body-pd" onload="printClock()">
	<!-- header -->
	<!-- <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <a class="navbar-brand">
            <button class="btn ms-2" type="button">
                <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
            </button>
        </a>
    </nav> -->
	<nav
		class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100"
		style="position: absolute">
		<header
			class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/" class="navbar-brand"> <img class="img-fluid"
				src="/images/logo2.png" alt="logo2" style="height: 40px;"> <use
					xlink:href="#bootstrap"></use> </svg>
			</a>

			<ul
				class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
				<jsp:include page="../navHeader.jsp"></jsp:include>
			</ul>
		</header>
	</nav>
	<!-- /header -->
	<!-- side nav bar -->
	<div class="l-navbar" id="navbar">
		 <nav class="navv">
			<div>
				<div class="nav__brand">
					<ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
				</div>
				<div class="nav__list">
					<div href="/manager/notice/noticeList" class="nav__link collapses">
						<a style="text-decoration: none; color: white;"  href="/notice/noticeList"><ion-icon name="folder-outline" class="nav__icon"></ion-icon>
						</a>
						<span class="nav_name">공지사항 관리</span>

						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

						<ul class="collapse__menu" style="width: 180px;">
							<a href="/manager/noticeWrite" class="collapse__sublink">공지사항 글쓰기</a>
						</ul>
					</div>
				</div>
				<a href="/logout" class="nav__link"> <ion-icon
						name="log-out-outline" class="nav__icon"></ion-icon> <span
					class="nav_name">Log out</span>
				</a>
			</div>
		</nav>
	</div>
	<!-- /side nav bar -->
	<!-- main content -->
	<div class="container-fluid w-100"
		style="background-color: rgb(214, 225, 237)">
		<div class="row">


			<!-- content header -->
			<jsp:include page="../contentHeader.jsp"></jsp:include>
			<!-- card header -->
			<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold"
				style="background-color: rgb(39, 40, 70); height: 40px;">
				<i class="bi bi-bookmark-fill me-2"></i>공지사항관리 <i
					class="bi bi-chevron-right"></i> 공지사항 작성
			</div>
			<!-- card content -->
			<div class="col-12 rounded-bottom overflow-auto bg-light p-3"
				style="min-height: 550px;">
				<h3>공지사항 작성</h3>
				<hr>
				<form action="/manager/noticeSave" method="post">
					<input type="hidden" id=writerUserid name="writerUserid" value="${member.userid}">
					<div style="margin: 10px;">
						<label for="exampleFormControlInput1" class="form-label">글제목</label>
						<input type="text" class="form-control"
							id="noticeTitle exampleFormControlInput1" name="noticeTitle"
							placeholder="제목을 입력하세요." required="required">
					</div>
					<div style="margin: 10px;">
						<label for="exampleFormControlTextarea1" class="form-label">내용</label>
						<textarea class="form-control" rows="3"
							id="noticeContent exampleFormControlTextarea1"
							name="noticeContent" style="height: 300px;" required="required"></textarea>
					</div>
					<div style="margin: 10px; width: 100px;">
						<select class="form-select" aria-label="Default select example"
							id="noticeType" name="noticeType">
							<option selected disabled="disabled">구분</option>
							<option value="allContent">통합</option>
							<option value="ROLE_STUDENT">학생</option>
							<option value="ROLE_PROFESSOR">교수</option>
							<option value="ROLE_MANAGER">교직원</option>

						</select>
					</div>
					<div style="margin: 10px;">
						<button type="submit" class="btn btn-outline-primary">등록</button>
					</div>
				</form>
			</div>
		</div>
		<!-- footer -->
		<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
			@2022 ChoongAng University. All Rights Reserved. </footer>
	</div>
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<!-- JS -->
	<script src="/js/main.js"></script>
</body>
</html>