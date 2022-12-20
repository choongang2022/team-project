<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ include file="header.jsp"%>
<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="http://code.jquery.com/ui/1.8.18/themes/base/jquery-ui.css" type="text/css" />  
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>  
<script src="http://code.jquery.com/ui/1.8.18/jquery-ui.min.js"></script>
<script type="text/javascript">
    $(document).ready(function () {
            $.datepicker.setDefaults($.datepicker.regional['ko']); 
            $( "#startDate" ).datepicker({
            	
                 changeMonth: true, 
                 changeYear: true,
                 nextText: '다음 달',
                 prevText: '이전 달', 
                 dayNames: ['일요일', '월요일', '화요일', '수요일', '목요일', '금요일', '토요일'],
                 dayNamesMin: ['일', '월', '화', '수', '목', '금', '토'], 
                 monthNamesShort: ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'],
                 monthNames: ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'],
                 dateFormat: "yymmdd",
                 minDate: 0,  // 선택할수있는 최소날짜, ( 0 : 오늘 이전 날짜 선택 불가)
                 onClose: function( selectedDate ) {    
                      //시작일(startDate) datepicker가 닫힐때
                      //종료일(endDate)의 선택할수있는 최소 날짜(minDate)를 선택한 시작일로 지정
                     $("#endDate").datepicker( "option", "minDate", selectedDate );
                 }    
 
            });
            $( "#endDate" ).datepicker({
                 changeMonth: true, 
                 changeYear: true,
                 nextText: '다음 달',
                 prevText: '이전 달', 
                 dayNames: ['일요일', '월요일', '화요일', '수요일', '목요일', '금요일', '토요일'],
                 dayNamesMin: ['일', '월', '화', '수', '목', '금', '토'], 
                 monthNamesShort: ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'],
                 monthNames: ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'],
                 dateFormat: "yymmdd",
                 minDate: 0,
                 onClose: function( selectedDate ) {    
                     // 종료일(endDate) datepicker가 닫힐때
                     // 시작일(startDate)의 선택할수있는 최대 날짜(maxDate)를 선택한 시작일로 지정
                     $("#startDate").datepicker( "option", "maxDate", selectedDate );
                 }    
 
            });    
    });
    
    </script>


<meta charset="UTF-8">
<!-- bottSTrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<!-- <script src="http://code.jquery.com/jquery-latest.min.js"></script> -->
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">

    <title>SideBar sub menus</title>
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
               <a href="/manager/approval" class="nav__logo">학사관리</a>
            </div>
            <div class="nav__list">
               <div href="" class="nav__link collapses">
                  <!-- <ion-icon name="folder-outline" class="nav__icon"></ion-icon> -->
                  <!-- <i class="bi bi-gear-fill nav__icon" name="folder-outline"></i> -->
                  <i class="bi bi-mortarboard-fill nav__icon" name="folder-outline"></i>
                  <span class="nav_name">학사관리</span>

                  <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                  <ul class="collapse__menu" style="width: 200px;">
                     <a href="/manager/studentManage" class="collapse__sublink">학생관리</a></br>
                     <a href="/manager/professorManage" class="collapse__sublink">교수관리</a></br>
                     <a href="/manager/EvaManagementForm" class="collapse__sublink">강의 평가 관리</a></br>
                     <a href="/manager/updateFormEvaluation" class="collapse__sublink">강의 평가 수정</a></br>
                  </ul>
               </div>
            </div>
            <a href="/logout" class="nav__link"> <ion-icon
                  name="log-out-outline" class="nav__icon"></ion-icon> <span
               class="nav_name">로그아웃</span>
            </a>
         </div>
      </nav>
   </div>
    <!-- /side nav bar -->
<!------- main content ------------>
<div class="container-fluid w-100 row" style=" background-color: rgb(214, 225, 237);">
   <!-- <div class="row"> -->
					
      <!-- content header -->
      <jsp:include page="contentHeader.jsp"></jsp:include>
                    <!-- card content -->  
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>교직원  <i class="bi bi-chevron-right"></i>&nbsp;기간 관리
                    </div>
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                       <!-------------------------  본문 ---------------------------------------->
                         <!--메인 제목-->
	                        <div class="mt-3 mb-3 ">                    
	                       	  <span class="fs-2 fw-bold" >수강신청 | 장바구니 기간 등록 </span>       
	                       	  <hr>                  
	                        </div>
	                        
	                                            
                       <form action="registerTime" >
							<div class="mb-3 ms-4" style="margin-top: 30px;">                    
	                       	  <span class="fs-5 fw-bold">${year }년도 ${semester }학기</span>                         
	                        </div>
	                        <br>
	                        <div class="fw-bold ms-4">
		                        <div class="ms-2">
								<i class="bi bi-clipboard-check-fill"></i>&nbsp; 일정선택&nbsp; :&nbsp;
								<select name="select" required="required">
									<option label="일정선택"/>
									<option value="apply">수강신청</option>
									<option value="like">장바구니</option>	
								</select>
								<p/>
							
								
								<input type="hidden" value="${year }" name="year">
								<input type="hidden" value="${semester }" name="semester">
								
								<p/>
								
								<i class="bi bi-calendar-check"></i>&nbsp; 시작일 &nbsp;<input type="text" id="startDate" name="start" required="required">&nbsp; ~ &nbsp;<i class="bi bi-calendar-check-fill"></i>&nbsp;&nbsp;마감일 &nbsp;<input type="text" id="endDate" name="end" required="required">
								&nbsp;<input type="submit" value="등록">
								
								</div>
						
							</div>
					
					</form>
                       <!---------------------------------------------------------------------->
                                       
                    </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        footer
                    </footer>    
                </div>
            </main>
        </div>
    </div>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>
