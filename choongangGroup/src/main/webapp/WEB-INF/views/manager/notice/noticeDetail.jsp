<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"  %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ include file="../header.jsp" %>
<!DOCTYPE html>
<html>
<head>
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
<!-- Ajax  -->
<script type="text/javascript">

	/**=== 게시판 수정 ===*/
	function updateFormNotice(){
		alert("수정폼");
		$("#noticeTitle1").hide();
		$("#noticeContent1").hide();
		$("#beforeButton").hide();
		$("#deleteButton").hide();
		$("#noticeTitle2").show();
		$("#noticeContent2").show();
		$("#afterButton").show();
	}
	
	function updateNotice(){
		alert("수정시작!");
		var vnoticeNum = $("#noticeNum").val();
		var vnoticeTitle = $("#noticeTitle2").val();
		var vnoticeContent = $("#noticeContent2").val();
		var vnoticeHit = $("#noticeHit").val();
		var vnoticeType = $("#noticeType").val();
			
		console.log("vnoticeNum -> " + vnoticeNum);
		console.log("vnoticeTitle -> " + vnoticeTitle);
		console.log("vnoticeNum -> " + vnoticeContent);
		console.log("vnoticeType -> " + vnoticeType);
		
		if(vnoticeTitle === null || !vnoticeTitle){
			alert("제목을 입력하세요.");
			return false;
		}
		if(vnoticeContent === null || !vnoticeContent){
			alert("내용을 입력하세요.");
			return false;
		}
		
		
				
		$.ajax({
			url		 : "/manager/updateNotice",
			data	 : { noticeNum : vnoticeNum , noticeTitle : vnoticeTitle, noticeContent : vnoticeContent, noticeHit : vnoticeHit , noticeType : vnoticeType },
			dataType : 'text',
			success	 : function(data){
				alert("수정완료!");
				$("#noticeTitle1").val(vnoticeTitle);
				$("#noticeContent1").val(vnoticeContent);
			}
		});
		$("#noticeTitle1").show();
		$("#noticeContent1").show();
		$("#noticeTitle2").hide();
		$("#noticeContent2").hide();
		$("#beforeButton").show();
		$("#afterButton").hide();
		$("#deleteButton").show();

	}
	
	/* 게시물 삭제 */
	function deleteNotice(){
		console.log("삭제 시작");
		var dnoticeNum = $("#noticeNum").val();
		console.log("dnoticeNum -> " + dnoticeNum);
		
		$.ajax({
			url 	: "/manager/deleteNotice",
			data	: {noticeNum : dnoticeNum},
			success : function(data){
				alert("삭제 되었습니다.");
				location.href = "/notice/noticeList";
			}
		});
	}
	
	
	

</script>
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
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
        <div class="row">
            
            
            <!-- content header -->
            <jsp:include page="../contentHeader.jsp"></jsp:include>
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>공지사항 관리 <i class="bi bi-chevron-right"></i> <a style="text-decoration: none; color: white;"  href="/notice/noticeList">공지사항</a> <i class="bi bi-chevron-right"></i> 상세내용
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
		                	<div class="container">
		                      	<div class="mb-3">                  		
			                      	<input id="noticeNum" type="hidden" value="${notice.noticeNum}">
			                      	<input id="noticeHit" type="hidden" value="${notice.noticeHit}">
			                      	<input id="noticeType" type="hidden" value="${notice.noticeType}">    
			                   </div>                 	
		                       <div class="mb-3">
		                     		<label class="form-label">제목</label>
		                     		<input id="noticeTitle1" name="noticeTitle" type="text" class="form-control" value="${notice.noticeTitle}" readonly>
		                     		<input id="noticeTitle2" type="text" class="form-control" value="${notice.noticeTitle}" style="display: none;">
		                     	</div>
		                     	<div>
		                     		<label class="form-label">내용</label>
		                     		<textarea id="noticeContent1" name="noticeContent" class="form-control" rows="3" style="height: 300px;" readonly="readonly" >${notice.noticeContent}</textarea>
		                     		
		                     		<textarea id="noticeContent2" class="form-control" rows="3" style="height: 300px; display: none;">${notice.noticeContent}</textarea>            	
		                      	</div>
		                      	<c:set value='${member.userid}' var="userid"/>
									<c:if test="${notice.writer.userid eq userid}">
		                      	<div style="margin: 10px;">
			                        	<button id="beforeButton" type="button" class="btn btn-outline-primary"  onclick="updateFormNotice()">수정</button>
			                        	<button id="afterButton" type="button" class="btn btn-outline-primary"  onclick="return updateNotice()" style="display: none;">수정완료</button>
			                        	<button id="deleteButton" type="button" class="btn btn-outline-danger" onclick="deleteNotice()">삭제</button>	    
			                    </div>
			                    </c:if>
		                  	 </div>
                  	</div>

                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        @2022 ChoongAng University. All Rights Reserved.
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