<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
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

.orderInfo {
	border: 5px solid #eee;
	padding: 10px 20px;
	margin: 20px 0;
}

.orderInfo span {
	font-size: 20px;
	font-weight: bold;
	display: inline-block;
	width: 90px;
}

.orderView li {
	margin-bottom: 20px;
	padding-bottom: 20px;
	border-bottom: 1px solid #999;
}

.orderView li::after {
	content: "";
	display: block;
	clear: both;
}

.thumb {
	float: left;
	width: 200px;
}

.thumb img {
	width: 200px;
	height: 200px;
}

.bookInfo {
	float: right;
	width: calc(100% - 220px);
	line-height: 2;
}

.bookInfo span {
	font-size: 20px;
	font-weight: bold;
	display: inline-block;
	width: 100px;
	margin-right: 10px;
}

.orderInfo {
	border: 5px solid #eee;
	padding: 10px 20px;
	margin: 20px 0;
}

.orderInfo span {
	font-size: 20px;
	font-weight: bold;
	display: inline-block;
	width: 90px;
}

.orderView li {
	margin-bottom: 20px;
	padding-bottom: 20px;
	border-bottom: 1px solid #999;
}

.orderView li::after {
	content: "";
	display: block;
	clear: both;
}

.thumb {
	float: left;
	width: 200px;
}

.thumb img {
	width: 200px;
	height: 200px;
}

.bookInfo {
	float: right;
	width: calc(100% - 220px);
	line-height: 2;
}

.bookInfo span {
	font-size: 20px;
	font-weight: bold;
	display: inline-block;
	width: 100px;
	margin-right: 10px;
}
</style>
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript" src="https://cdn.iamport.kr/js/iamport.payment-1.1.8.js"></script>
<script>
	function requestPay(){
		console.log("amount -> "+ $('#amount').val());
		var billState = $('#billState').val();
		var state = $("#state").val();
		if(state != '????????????'){
		if(billState != '????????????'){
		//var IMP = window.IMP; // ????????????
		IMP.init('imp47214821');
		IMP.request_pay({
			pg : 'kakaopay',
			pay_method : 'card',
			merchant_uid : 'merchant_' + new Date().getTime(),
			name : '?????? ?????????',
			amount : $('#amount').val(),
			buyer_email : 'abcMartek@siot.do',
			buyer_name : '?????????', //????????? ??????
			buyer_tel : '010-5014-6344',
			buyer_addr : '',
			buyer_postcode : ''
		}, function(rsp) {
			if(rsp.success){
				
			var billState = $("#state2_btn").val();
			var orderId = $("#orderId").val();
			console.log("orderId"+orderId);
			console.log("billState"+billState);
			var data = {
					orderId:orderId,
					billState:billState
			};

			$.ajax({
				url : "/student/billChange",
				type : "post",
				data : data,
				success : function(rsp) {
					alert("????????? ?????????????????????.");
					location.href = "/student/orderList";
				},
				error : function() {
					alert("????????? ?????????????????????.");
					location.href = "/student/orderList";
						}
					});
				}
		});
		}else{
			alert("?????? ?????? ??? ??? ?????????.");
		}
		}else{
			alert("?????? ?????? ??? ????????????.");
		}
	}
</script>
<script type="text/javascript">
document.addEventListener("DOMContentLoaded", function(){
	chk();
	});
	function chk(){
		var state = $("#state").val();
		var billState = $("#billState").val();
		/* const target = document.getElementById('#state1_btn');
		const tar = document.getElementById('#state2_btn');  */
		if(state == '?????? ??????' | billState == '?????? ??????' ){
			$("#state1_btn").attr('disabled', 'disabled');
			$("#state2_btn").attr('disabled', 'disabled');
		}
		else {
				$("#state1_btn").attr('disabled',false);
				$("#state2_btn").attr('disabled',false);
		}
		/* const target = document.getElementById('#state1_btn');
		const tar = document.getElementById('#state2_btn');  */
		/* if(billState == '?????? ??????'){
			$("#state1_btn").attr('disabled', 'disabled');
			$("#state2_btn").attr('disabled', 'disabled');
		}
		else {
				$("#state1_btn").attr('disabled',false);
				$("#state2_btn").attr('disabled',false);
		} */
	}
/* 	$(document).ready(function(){
	}); */
	
		
</script> 
</head>
<body id="body-pd">
	<!-- header -->
	<nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
		<header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/student/main" class="navbar-brand  ms-3">
				<img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"></svg>
			</a>

			<!-- <ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
				<li><a href="#" class="nav-link px-2 link-secondary">Home</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Features</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Pricing</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">FAQs</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">About</a></li>
			</ul> -->
		</header>
	</nav>
	
	<!-- side nav bar -->
	<%-- <div class="l-navbar" id="navbar">
		<nav class="navv">
			<div class="nav__brand">
				<ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
				<a href="#" class="nav__logo"></a>
			</div>
			<a href="/professor/calenderForm" class="nav__link active">
				<i class="bi bi-calendar-plus nav__icon" ></i>
				<span class="nav_name">?????????</span>
			</a>
			<a href="/logout" class="nav__link">
				<ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
				<span class="nav_name">Log out</span>
			</a>
			

			<div href="#" class="nav__link collapses ">
				<ion-icon name="folder-outline" class="nav__icon"></ion-icon>
				<span class="nav_name">????????????</span>
				<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

				<ul class="collapse__menu  " style="width: 180px;">
					<a href="#" class="collapse__sublink mt-2 mb-2" style="font-size: 0.875rem;">???????????????</a>
					<a href="/professor/lecMgMain?userid=${userid}" class="collapse__sublink mb-1 ms-0" style="font-size: 0.875rem;">????????????</a>
					<a href="#" class="collapse__sublink ms-3" style="font-size: 0.8rem;">???????????????</a>
					<a href="#" class="collapse__sublink ms-3 mb-2"  style="font-size: 0.8rem;">????????????</a>
					
					<a href="#" class="collapse__sublink mb-2" style="font-size: 0.875rem;">???????????????</a>
					<a href="/professor/lecCreateList" class="collapse__sublink mb-2" style="font-size: 0.875rem;">????????????</a>
					<!-- <a href="#" class="collapse__sublink mb-1" style="font-size: 0.875rem;">????????????</a>
					<a href="#" class="collapse__sublink ms-3"  style="font-size: 0.8rem;">???????????????</a>
					<a href="#" class="collapse__sublink ms-3 mb-2"  style="font-size: 0.8rem;">????????????</a> -->
					<a href="/professor/lecScore" class="collapse__sublink mb-2" style="font-size: 0.875rem;">????????????</a>
					<a href="#" class="collapse__sublink mb-2" style="font-size: 0.875rem;">???&#183;?????? ??????</a>
					<a href="#" class="collapse__sublink mb-2" style="font-size: 0.875rem;">??????????????????</a>
				</ul>
			</div>

			<div class="nav__list">
				<div href="#" class="nav__link collapses">
	                 <ion-icon name="folder-outline" class="nav__icon"></ion-icon>
	                 <span class="nav_name">Projects</span>
	
	                 <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>
	
	                 <ul class="collapse__menu">
	                     <a href="#" class="collapse__sublink">Data</a>
	                     <a href="#" class="collapse__sublink">Group</a>
	                     <a href="#" class="collapse__sublink">Members</a>
	                 </ul>
	             </div>
				<a href="#" class="nav__link">
					<ion-icon name="chatbubbles-outline" class="nav__icon"></ion-icon>
					<span class="nav_name">??????</span>
				</a>
				<!-- <a href="#" class="nav__link">
					<ion-icon name="people-outline" class="nav__icon"></ion-icon>
					<span class="nav_name">??????????????????</span>
				</a> -->
				<a href="#" class="nav__link">
					<ion-icon name="settings-outline" class="nav__icon"></ion-icon>
					<span class="nav_name">??????????????????</span>
				</a>
				<a href="/logout" class="nav__link">
					<ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
					<span class="nav_name">Log out</span>
				</a>
			</div>
		</nav>
	</div> --%>
	
	<!-- side nav bar -->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                   <!--  <a href="#" class="nav__logo">????????????</a> -->
                </div>
                <div class="nav__list">
                   <div href="#" class="nav__link collapses">
                        <i class="bi bi-person-rolodex"></i>
                        <span class="nav_name">????????????</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/listEmp" class="collapse__sublink">???????????? ??????</a></li>
                            <li><a href="/student/lectureListForm" class="collapse__sublink">???????????? ??????</a></li>
                            
                            <li><a href="/student/timetable" class="collapse__sublink">????????? ??????</a></li>
                           

                        </ul>
                    </div>
                    

               <a href="/student/gradeList" class="nav__link">
                       <i class="bi-mortarboard"></i>
                       <span class="nav_name">&nbsp;?????? ??????</span>
                   </a>
      

               <a href="/student/evaluationList" class="nav__link">
                       <i class="bi-pencil"></i>
                       <span class="nav_name">&nbsp;?????? ??????</span>
                   </a>


               <a href="/student/applyIndex" class="nav__link">
                       <i class="bi bi-box-arrow-up-right"></i>
                       <span class="nav_name">&nbsp;?????? ??????</span>
                   </a>
                    <div href="/student/shopList" class="nav__link collapses">
                        <i class="bi bi-book"></i>
                        <span class="nav_name">&nbsp;?????? ??????</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/shopList" class="collapse__sublink">?????? ??????</a></li>
                            <li><a href="/student/cartList" class="collapse__sublink">????????????</a></li>
                            <li><a href="/student/orderList" class="collapse__sublink">?????? ??????</a></li>
                        </ul>
                    </div>
                </div>
                <a href="/logout" class="nav__link">
                    <i class="bi-power"></i>
                    <span class="nav_name">&nbsp; Log out</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->

	<!-- main content -->
   <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
      <div class="row">
      
         <!-- content header -->
         <div class="col-12 px-5 py-4" style=" background-color: rgb(95, 142, 241)">
            <div class="d-flex flex-row mb-2 mt-2">
               <div>
                  <span class="text-white h4">???????????????. <span class="fw-bold">${name}</span>???!</span>
               </div>
               <div class="border border-1 border-white rounded-pill text-white ms-2"  style="height: 25px;">
                  <div class="font09 align-items-center">&nbsp; ??????  &nbsp;</div>
               </div>
               <div><i class="text-white bi-gear-fill mx-2">  </i></div>
            </div>
            <div class="row">

            <div>
               <span class="text-white font09">${major}???&nbsp; &nbsp; ${grade}&nbsp;?????? </span>
            </div>
            </div>
            <div class="d-flex flex-low mb-2">
               <div><i class="bi bi-envelope-fill text-white"></i></div>
               <div><span class="text-white ms-2 font09">${email}</span></div>
            </div>

         </div>
         <div class="row m-5">
				
					<!-- card header -->
                    <div class="col-9 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px; margin-left: 150px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>?????? ??????<i class="bi bi-chevron-right"></i>?????? ??????<i class="bi bi-chevron-right"></i>?????? ?????? ??????
                    </div>
				
					<!-- card content -->  
<!-- 			<main class="col-9 h-100 w-50" style="margin-left: 400px;">
				<div class="row m-5">
					<div class="row mb-2 pe-0 ps-2" >
 -->						<div class="col-9 rounded-bottom overflow-auto bg-light p-3" style="min-height: 400px; margin-left: 150px;"> 
						
								<h1>
								<div class="d-flex justify-content-end">
									<a href="/student/shopList"><i class="bi bi-book" style="color: black; margin-right: 20px;"></i></a>
									<a href="/student/cartList"><i class="bi bi-cart2" style="color: black; margin-right: 20px;"></i></a>
									<a href="/student/orderList"><i class="bi bi-receipt" style="color: black; margin-right: 20px;"></i></a>
								</div>
								</h1>
							<h2>?????? ?????? ??????</h2>
							<hr>
								<section id="content">
									<div class="orderInfo">
										<c:forEach items="${orderView}" var="orderView" varStatus="status">
							
											<c:if test="${status.first}">
												<p>
													<span>?????????</span>
													${orderView.orderName}
												</p>
												<p>
													<span>??????</span>
													<fmt:formatNumber pattern="###,###,###" value="${orderView.amount}" /> ???
												</p>
												<p>
													<span>????????????</span>${orderView.bookLoca}
												</p>
												<p>
												<div class="StateChange">
													<form action="/student/orderView" role="form" method="post"	id="stateForm" name="stateForm" class="stateForm">
													<span>??????</span>${orderView.state }
														<input type="hidden" name="userId" value="${orderView.userId }">
														<input type="hidden" name="orderId" value="${orderView.orderId}" />
														<input type="hidden" name="state" id="state" class="state"	value="${orderView.state }" />
														<input type="hidden" name="billState" id="billState" class="billState"	value="${orderView.billState }" />
														<button type="submit" name="state1_btn" id="state1_btn"	class="state1_btn" value="?????? ??????" onclick="btnDisabled()" style="margin-left: 20px;" >?????? ??????</button>
													</form>
												</div>
												</p>
												<p>
												<div class="StateChange">
													<p>
													<form action="/student/billChange" role="form" method="post"	id="stateForm" name="stateForm" class="stateForm">
													<span>????????????</span>${orderView.billState }
														<input type="hidden" name="userId"  value="${orderView.userId }">
														<input type="hidden" name="orderId" id="orderId" value="${orderView.orderId}" />
														<input type="hidden" name="amount" id="amount" value="${orderView.amount}" />
														<input type="hidden" name="state" id="state" class="state"	value="${orderView.state }" />
														<input type="hidden" name="billState" id="billState" class="billState"	value="${orderView.billState }" />
															<button type="button" name="state2_btn" id="state2_btn"	class="state2_btn" value="?????? ??????" onclick="requestPay()" style="margin-left: 15px;">??????</button>
													</form>
												</div>
												</p>
											</c:if>
							
										</c:forEach>
									</div>
							
									<ul class="orderView">
										<c:forEach items="${orderView}" var="orderView">
											<li>
												<div class="thumb">
													<img src="${orderView.bookThumbImg}"
														style="width: 200px; height: 150px; object-fit: contain; float: left;" />
												</div>
												<div class="bookInfo">
													<p>
														<span>?????????</span>
														${orderView.bookName}<br /> 
														<span>?????? ??????</span>
														<fmt:formatNumber pattern="###,###,###"	value="${orderView.bookPrice}" /> ???<br /> 
														<span>?????? ??????</span>
														${orderView.cartStock} ???<br /> 
														<span>????????????</span>
														<fmt:formatNumber pattern="###,###,###"	value="${orderView.bookPrice * orderView.cartStock}" />	???<br /> 
														<span>??????</span>${orderView.state }<br/>
														<span>????????????</span>${orderView.billState }
												</div>
											</li>
										</c:forEach>
									</ul>
								</section>
						</div>
					</div>
					
					<!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						@2022 ChoongAng University. All Rights Reserved.
					</footer> 
				</div>
			</main>
		</div>
	</div>
	
<!-- NavBar ?????? IONICONS -->
<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
<!-- JS -->
<script src="/js/main.js"></script>
</body>
</html>

