
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<style type="text/css">

.passUpdate:link, .passUpdate:visited {
    background-color: #12192c;
     padding: 6px 12px;
     text-align: center;
     text-decoration: none;
     display: inline-block;
     color: white;
     border-radius: 0.375rem;
}





</style>

<meta charset="UTF-8">
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
<link rel="stylesheet" href="/css/styles.css">

    <title>SideBar sub menus</title>
</head>

<body class="" id="body-pd">
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
            <li><a href="#" class="nav-link px-2 link-secondary">Home</a></li>
            <li><a href="#" class="nav-link px-2 link-dark">Features</a></li>
            <li><a href="#" class="nav-link px-2 link-dark">Pricing</a></li>
            <li><a href="#" class="nav-link px-2 link-dark">FAQs</a></li>
            <li><a href="#" class="nav-link px-2 link-dark">About</a></li>
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
                   <!--  <a href="#" class="nav__logo">카테고리</a> -->
                </div>
                <div class="nav__list">
                   <div href="#" class="nav__link collapses">
                        <i class="bi bi-person-rolodex"></i>
                        <span class="nav_name">학사관리</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/listEmp" class="collapse__sublink">학적정보 조회</a></li>
                            <li><a href="/student/lectureListForm" class="collapse__sublink">강의목록 조회</a></li>
                            
                            <li><a href="/student/timetable" class="collapse__sublink">시간표 조회</a></li>
                           

                        </ul>
                    </div>
                    

               <a href="/student/gradeList" class="nav__link">
                       <i class="bi-mortarboard"></i>
                       <span class="nav_name">&nbsp;성적 관리</span>
                   </a>
      

               <a href="/student/evaluationList" class="nav__link">
                       <i class="bi-pencil"></i>
                       <span class="nav_name">&nbsp;강의 평가</span>
                   </a>


               <a href="/student/applyIndex" class="nav__link">
                       <i class="bi bi-box-arrow-up-right"></i>
                       <span class="nav_name">&nbsp;수강 신청</span>
                   </a>
                    <div href="/student/shopList" class="nav__link collapses">
                        <i class="bi bi-book"></i>
                        <span class="nav_name">&nbsp;교재 구매</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/shopList" class="collapse__sublink">교재 목록</a></li>
                            <li><a href="/student/cartList" class="collapse__sublink">장바구니</a></li>
                            <li><a href="/student/orderList" class="collapse__sublink">주문 목록</a></li>
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
            
            
         <!-- main content -->
   <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
      <div class="row">
      
         <!-- content header -->
         <div class="col-12 px-5 py-4" style=" background-color: rgb(95, 142, 241)">
            <div class="d-flex flex-row mb-2 mt-2">
               <div>
                  <span class="text-white h4">안녕하세요. <span class="fw-bold">${member.name}</span>님!</span>
               </div>
               <div class="border border-1 border-white rounded-pill text-white ms-2"  style="height: 25px;">
                  <div class="font09 align-items-center">&nbsp; 학생  &nbsp;</div>
               </div>
               <div><i class="text-white bi-gear-fill mx-2">  </i></div>
            </div>
            <div class="row">

            <div>
               <span class="text-white font09">${member.major}과&nbsp; &nbsp; ${member.grade}&nbsp;학년 </span>
            </div>
            </div>
            <div class="d-flex flex-low mb-2">
               <div><i class="bi bi-envelope-fill text-white"></i></div>
               <div><span class="text-white ms-2 font09">${member.email}</span></div>
            </div>

         </div>
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i class="bi bi-chevron-right"></i>학적정보 <i class="bi bi-chevron-right"></i>학적조회
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                       
 
                     

       <!--    *********************************************** 학적조회************************************      -->
       
       
       

		<!--이미지   -->
		
					<!--이미지   -->
			<div  style="width: 1000px; height: 250px; ">
			  <div class="row g-0">
				   <div class="col-md-4">
				      <img  id="preview"    src="../upload/hj/${member.image}" style="width: 600px; height: 200px;"   class="img-fluid rounded-start" alt="이미지">
				      <label for="file1">
                      
                    </label>
                   
				    <input type="file" style="display: none;"  onchange="readURL(this)"   name="file1"  id="file1" value="${member.image}">
				    
				   </div>
				        
			  </div>
				 
			</div>
		
		
		
		
<%-- 		
		
		<div  style="width: 200px; height: 200px; ">
		    <div class="row g-0">
		     
		      <img  id="preview"    src="../upload/hj/${member.image}" style="width: 200px; height: 200px;"   class="img-fluid rounded-start" alt="이미지">
		  
		                       
		     </div>
		 
		</div>
 --%>


		<table id="table1"  class="table table-striped-columns" style="table-layout: fixed;">
		
					<tr><th>성명</th><td>${member.name } </td> 			<th>학번</th><td>${member.userid }</td>          <th>국적</th><td>${member.nation }</td></tr>
					<tr><th>휴대전화</th><td> ${member.phone }</td>			<th>학년</th><td>${member.grade}</td>          <th>비상연락망</th><td>${member.subphone }</td></tr>
					<tr><th>성별</th><td>${member.gender }</td> 			 <th>학적상태</th><td>${member.stud_status }</td>       <th>E-Mail</th><td>${member.email }</td></tr>
					<tr><th>입학 일자</th><td>${member.admission}</td>          <th>입학전형</th><td>${member.adm_type }</td>      <th>지도교수</th><td>${member.main_prof }</td></tr> 
					<tr><th>전공(소속학과)</th><td>${member.major}</td> 			<th>부전공</th><td>${member.sub_major}</td>         <th>주소</th><td>${member.address }</td></tr> 
			 
			
		
		</table>
                <!-- 학적수정 버튼  -->
        <div>
             <label class="btn btn-secondary" for="option2" onclick="location.href='updateFormMember?userid=${member.userid}'" >학적수정</label>
             <a href="/updatePasswordForm" class="passUpdate">비밀번호 번경하기</a>
        </div>          
                       
                       
  <!--    *********************************************** 학적조회 end    ************************************      -->                      
                       
                       
                       
                       
                       
                    </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                     <jsp:include page="../footer.jsp"></jsp:include>
                     
                    </footer>    
                </div>
            </main>
        </ div>
    </div>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>





