<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ include file="header.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
<!-- bottSTrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles2.css">
<link rel="stylesheet" href="/css/stylesLec.css">
<style type="text/css">
#container_box table td {
	width: 100px;
}

section#container {
	padding: 20px 0;
	border-top: 2px solid #eee;
	border-bottom: 2px solid #eee;
}

section#container::after {
	content: "";
	display: block;
	clear: both;
}

aside {
	float: left;
	width: 200px;
}

div#container_box {
	float: right;
	width: calc(100% - 200px - 20px);
}

aside {
	float: left;
	width
	200px;
}

aside ul li {
	text-align: center;
	margin-bottom: 10px;
}

aside ul li a {
	display: block;
	width: 100%;
	padding: 10px 0;
}

aside ul li a:hover {
	background: #eee;
}

.inputArea {
	border: 1px;
	margin: 10px 0;
}

select {
	width: 100px;
}

label {
	display: inline-block;
	width: 70px;
	padding: 5px;
}

label[for='bookInfo'] {
	display: block;
}

input {
	width: 150px;
}

textarea#bookInfo {
	width: 400px;
	height: 180px;
}

section#content ul li {
	border: 5px solid #eee;
	padding: 10px 20px;
	margin-bottom: 20px;
}

section#content .orderList span {
	font-size: 20px;
	font-weight: bold;
	display: inline-block;
	width: 90px;
	margin-right: 10px;
}
</style>
<!-- <script type="text/javascript">

$(document).ready(function(){
   if($("#mainCheck").val() != "1") {
       location.href="/manager/managerMain";  
   }
   
});

</script> -->
</head>
<body class="" id="body-pd" onload="printClock()">
    <!-- header -->
    <!-- <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <a class="navbar-brand">
            <button class="btn ms-2" type="button">
                <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
            </button>
        </a>
    </nav> -->
    <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
          <a href="/" class="navbar-brand">
            <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
          </a>
    
          <ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
  			<jsp:include page="navHeader.jsp"></jsp:include>
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
                    <a href="/manager/main" class="nav__logo">교재관리</a>
                </div>
                <div class="nav__list">
                    <div href="${pageContext.request.contextPath}/manager/bookList" class="nav__link collapses">
						<!-- <ion-icon name="folder-outline" class="nav__icon"></ion-icon> -->
						<!-- <i class="bi bi-gear-fill nav__icon" name="folder-outline"></i> -->
						<i class="bi bi-book nav__icon" name="folder-outline"></i>
						<span class="nav_name">교재관리</span>

						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

						<ul class="collapse__menu" style="width: 200px;">
							<a href="/manager/bookList" class="collapse__sublink">교재 목록</i></a></br>
							<a href="/manager/bookInsert" class="collapse__sublink">교재 입력</i></a></br>
                            <a href="/manager/adminOrderList" class="collapse__sublink">주문 관리</i></a></br>
						</ul>
					</div>
                </div>
                <a href="/logout" class="nav__link">
                    <ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
                    <span class="nav_name">Log out</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->

	<!-- main content -->
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
		<div class="row">
		
			<!-- card header -->
			<jsp:include page="contentHeader.jsp"></jsp:include>
					<!-- card header -->
                    <div class="col-9 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px; margin-left: 150px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>교재 관리<i class="bi bi-chevron-right"></i>주문 현황
                    </div>
				
					<!-- card content -->  
<!-- 			<main class="col-9 h-100 w-50" style="margin-left: 400px;">
				<div class="row m-5">
					<div class="row mb-2 pe-0 ps-2" >
 -->						<div class="col-9 rounded-bottom overflow-auto bg-light p-3" style="min-height: 400px; margin-left: 150px;"> 
						
								<h1>
								<div class="d-flex justify-content-end">
									<a href="/manager/bookList"><i class="bi bi-book" style="color: black; margin-right: 20px;"></i></a>
									<a href="/manager/bookInsert"><i class="bi bi-pencil" style="color: black; margin-right: 20px;"></i></a>
									<a href="/manager/adminOrderList"><i class="bi bi-receipt" style="color: black; margin-right: 20px;"></i></a>
								</div>
								</h1>
							<h2 style="text-align: center;">주문 현황</h2>
							<div class="search_wrap">
							             <form action="/manager/SearchOrderList" id="searchForm" name="searchForm">
							             <select name="type">
							             	<option selected value="결제">선택</option>
											<option value="결제 대기" <c:if test="${billState eq '결제 대기'}">selected</c:if>>결제 대기</option>
											<option value="결제 완료" <c:if test="${billState eq '결제 완료'}">selected</c:if>>결제 완료</option>
							             </select>
							             <input type="submit" class="btn btn-ouyline-primary mr-2" value="검색"></input>
							             </form>
							</div>		
							<hr>
							<section id="content">
									<ul class="orderList">
										<c:forEach items="${orderList}" var="orderList">
											<li>
												<div>
													<p><span>주문번호</span><a href="/manager/adminOrderView?orderId=${orderList.orderId}">${orderList.orderId}</a></p>
													<p><span>주문자</span>${orderList.userId}</p>
													<p><span>수령인</span>${orderList.orderName}</p>
													<p><span>가격</span><fmt:formatNumber pattern="###,###,###" value="${orderList.amount}" /> 원</p>
													<p><span>상태</span>${orderList.state}</p>
													<p><span>결제상태</span>${orderList.billState}</p>
												</div>

											</li>
										</c:forEach>
									</ul>
							</section>

						</div>
					</div>
					
					<!-- footer -->
				</div>
			</main>
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						@2022 ChoongAng University. All Rights Reserved.
					</footer> 
		</div>
	</div>
	
	<!-- NavBar 관련 IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<!-- JS -->
	<script src="/js/main.js"></script>
</body>
</html>
