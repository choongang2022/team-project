<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ include file="header.jsp"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
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

    <title>교직원홈</title>
</head>
<script type="text/javascript">

$(document).ready(function(){
   if($("#mainCheck").val() != "1") {
       location.href="/manager/managerMain";  
   }
   
});

</script>
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
    <input type="hidden" id="mainCheck" value="${mainCheck}">
    <!-- /header -->
    <!-- side nav bar -->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                    <a href="/manager/main" class="nav__logo">교직원홈</a>
                </div>
                <a href="/logout" class="nav__link">
                    <ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
                    <span class="nav_name">로그아웃</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->
    <!-- main content -->
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
        <div class="row">
            <!-- content header -->
			<jsp:include page="contentHeader.jsp"></jsp:include>
                   
                    <!-- card content -->  
               <div class="row mb-2 pe-0 ps-2" >
                  <div class="col-md-5 me-3 rounded overflow-auto bg-light p-4" style="min-height: 400px;"> 
                     <h6 style="display: inline;">결재 대기중 목록</h6><p class="font08" style="display: inline; float: right;">총 <b style="color: red; ">${waitTotal}</b>개의 문서가 있습니다.</p><br>
                     <hr>
  					 <table class="table table-hover" style="font-size: 14px; text-align: center;">
						<tbody>
							<c:forEach var="wait" items="${waitList}">
								<tr>
									<td>
										<a href="apprWaitDetail?approval_no=${wait.approval_no}" style="color: black">${wait.approval_no}</a>
									</td>
									<td>${wait.writeday}</td>
									<td>${wait.approval_sort_name}</td>
									<td>${wait.title}</td>
									<c:if test="${wait.file_path ne null }">
										<td><i class="bi bi-file-earmark"></i></td>
									</c:if>
									<c:if test="${wait.file_path eq null }">
										<td>&nbsp;</td>
									</c:if>
									<c:if test="${wait.approval_status eq '0'}">
										<td>대기중<td>
									</c:if>
									<c:if test="${wait.approval_status eq '1'}">
										<td>승인<td>
									</c:if>
									<c:if test="${wait.approval_status eq '2'}">
										<td>반려<td>
									</c:if>
								</tr>
							</c:forEach>
						</tbody>
					 </table>
					 </br>
					 <h6 style="display: inline;">기안 진행중 목록</h6><p class="font08" style="display: inline; float: right;">총 <b style="color: red; ">${processTotal}</b>개의 문서가 있습니다.</p><br>
                     <hr>
                     <table class="table table-hover" style="font-size: 14px; text-align: center;">
						<tbody>
							<c:forEach var="process" items="${processList}">
								<tr>
									<td>
										<a href="apprProcessDetail?approval_no=${process.approval_no}" style="color: black">${process.approval_no}</a>
									</td>
									<td>${process.writeday}</td>
									<td>${process.approval_sort_name}</td>
									<td>${process.title}</td>
									<c:if test="${process.file_path ne null }">
										<td><i class="bi bi-file-earmark"></i></td>
									</c:if>
									<c:if test="${process.file_path eq null }">
										<td>&nbsp;</td>
									</c:if>
									<c:if test="${process.approval_status eq 0}">
										<td>대기중<td>
									</c:if>
									<c:if test="${process.approval_status eq 1}">
										<td>승인<td>
									</c:if>
									<c:if test="${process.approval_status eq 2}">
										<td>반려<td>
									</c:if>
								</tr>
							</c:forEach>
						</tbody>
					 </table>
                  </div>
                  <div class="col-md-3 me-5 rounded overflow-auto bg-light p-4" style="min-height: 400px;"> 
                     <h5>공지사항</h5><hr>
                     <table class="table table-hover" style="font-size: 14px;">
                       	<tbody>
                     		<c:forEach var="notice" items="${noticeList}" varStatus="status" begin="0" end="5">
                     			<tr>
	                     				<c:choose>
											<c:when test="${fn:length(notice.noticeTitle) gt 15}">
												<td><a
													href="/noticeDetail?noticeNum=${notice.noticeNum}" style="color: black;">${fn:substring(notice.noticeTitle, 0 , 14)}  ....</a></td>
											</c:when>
											<c:otherwise>
												<td><a
													href="/noticeDetail?noticeNum=${notice.noticeNum}" style="color: black;">${notice.noticeTitle }</a></td>
											</c:otherwise>
										</c:choose>									
	                     				<c:choose>
											<c:when test="${notice.createdDate != null}">
												<c:set var="DateValue" value="${notice.createdDate}" />
												<td>${fn:substring(DateValue,0,10)}</td>
											</c:when>
											<c:when test="${notice.modifiedDate != null}">
												<c:set var="DateValue" value="${notice.modifiedDate}" />
												<td>${fn:substring(DateValue,0,10)}</td>
											</c:when>
										</c:choose>
	                     		</tr>
                     		</c:forEach>
                     	</tbody>
                     </table>

                  </div>
                  <div class="col-md-2  rounded overflow-auto bg-light p-4" style="max-height: 300px;"> 
                      <h5>쪽지함</h5><hr>
                      <table>
                      	<c:forEach var="message" items="${messageList}" varStatus="status" begin="0" end="5">
                      		<tbody>
                      			<tr>
                      				<td><a href="/manager/messageDetail?messageId=${message.messageId }" style="color: black;">${message.senderName}</a>님 쪽지가 왔습니다!</td>
                      			</tr>       
                      		</tbody>
                      	</c:forEach>
                      </table>
                  </div>
               </div>
               
               <!-- footer -->
               <jsp:include page="../footer.jsp"></jsp:include>
            </div>
         </main>
      </div> 
   </div> <!-- container div end -->
   
   <!-- NavBar 관련 IONICONS -->
   <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
   <!-- JS -->
   <script src="/js/main.js"></script>
</body>
</html>