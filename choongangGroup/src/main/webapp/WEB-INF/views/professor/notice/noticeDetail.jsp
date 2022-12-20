<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"  %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
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
    <title>공지사항</title>
<!-- Ajax  -->
<script type="text/javascript">

</script>
</head>

<body class="" id="body-pd" onload="printClock()"  style="background-color: rgb(214, 225, 237)">
   <jsp:include page="../shortHeadrInfo.jsp"></jsp:include>
	
	<!-- side nav bar -->
	<jsp:include page="../sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->
    
    <!-- main content -->
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
        <div class="row">
            
            
            <!-- content header -->
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i><a style="text-decoration: none; color: white;"  href="/professor/notice/noticeList">공지사항</a> <i class="bi bi-chevron-right"></i> 상세내용
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;"> 
		                	<div class="container">
		                      	<div class="mb-3">                  		
			                      	<input id="noticeNum" type="hidden" value="${notice.noticeNum}">
			                      	<input id="noticeHit" type="hidden" value="${notice.noticeHit}">    
			                   </div>                 	
		                       <div class="mb-3">
		                     		<label class="form-label fw-bold">제목</label>
		                     		<input id="noticeTitle1" name="noticeTitle" type="text" class="form-control" value="${notice.noticeTitle}" readonly>
		                     		<input id="noticeTitle2" type="text" class="form-control" value="${notice.noticeTitle}" style="display: none;">
		                     	</div>
		                     	<div>
		                     		<label class="form-label fw-bold">내용</label>
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
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						<jsp:include page="../../footer.jsp"></jsp:include>
					</footer> 
					<!-- </footer>  -->
				</div>
			</main>
		</div> 
	</div> <!-- container div end -->
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<script src="/js/main.js"></script>
</body>
</html>