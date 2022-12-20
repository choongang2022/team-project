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
</head>
<script type="text/javascript">
	$(document).ready(function(){
		$("#chkAll").click(function() {
			if($("#chkAll").is(":checked")) $("input[name=chk]").prop("checked", true);
			else $("input[name=chk]").prop("checked", false);
		});
		
		$("input[name=chk]").click(function() {
			var total = $("input[name=chk]").length;
			var checked = $("input[name=chk]:checked").length;
			
			if(total != checked) $("#chkAll").prop("checked", false);
			else $("#chkAll").prop("checked", true); 
		});
	});
	
	function deleteMessage(){
		var valueArr = new Array();
		var messageList = $("input[name=chk]");
		console.log(messageList);
		for(var i = 0; i < messageList.length; i++){
			if(messageList[i].checked){
				valueArr.push(messageList[i].value);
			}
		}
		if (valueArr.length == 0){
			alert("선택된 쪽지가 없습니다.");
		}
		else{
			console.log(valueArr);
			$.ajax({
					url : "/manager/senderMessageDelete",
					data : { valueArr : valueArr },
					type : "POST",
					success : function (){
						alert("삭제 성공");
						location.href = "/manager/message/senderMessageList";
					}
			});
		}
	}

</script>
<body class="" id="body-pd" onload="printClock()">
<%

	session = request.getSession();

%>
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
                    <a href="/manager/message/messageList" class="nav__logo">쪽지함</a>
                </div>
                <div class="nav__list">
                    <a href="/manager/messageWriteForm" class="nav__link active">
                        <ion-icon name="chatbubbles-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">쪽지보내기</span>
                    </a>
                    <a href="/manager/message/messageList"" class="nav__link">
                        <ion-icon name="folder-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">받은 쪽지함</span>
                    </a>
                    <a href="/manager/message/senderMessageList" class="nav__link">
                        <ion-icon name="folder-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">보낸 쪽지함</span>
                    </a>
<!--                     <div href="#" class="nav__link collapses">
                        <ion-icon name="people-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">Team</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu">
                            <a href="#" class="collapse__sublink">Data</a>
                            <a href="#" class="collapse__sublink">Group</a>
                            <a href="#" class="collapse__sublink">Members</a>
                        </ul>
                    </div> -->
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
            
            
            <!-- content header -->
            <jsp:include page="../contentHeader.jsp"></jsp:include>
            
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>보낸 쪽지함
                    </div>
                    <!-- card content -->  
                  <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                      <table class="Notice-table table table-striped">
					    <thead>
					    <tr>
					      <!--   <th>번호</th> -->
					      	<th>
					      		<input type="checkbox" name="chkAll" id="chkAll">
					      	</th>
					        <th>이름</th>
					        <th>제목</th>
					        <th>내용</th>
					        <th>보낸시간</th>
					    </tr>
					    </thead>
					    <tbody>
					    <c:forEach items="${messageList}" var="message" varStatus="status">
					    <tr>
					    	<td>
					    		<input type="checkbox" name="chk" value="${message.messageId}">
					    	</td>
					    	<td>${message.senderName}</td>
					    	<td>
						    	<c:choose>
						    		<c:when test="${fn:length(message.messageTitle) gt 11 }">
						    			${fn:substring(message.messageTitle, 0, 10)} ....
						    		</c:when>
						    		<c:otherwise>
						    			${message.messageTitle}
						    		</c:otherwise>
						    	</c:choose>
					    	</td>
					    	<td>
					    		<c:choose>
						    		<c:when test="${fn:length(message.messageContent) gt 21 }">
						    			<a href="/manager/senderMessageDetail?messageId=${message.messageId}">${fn:substring(message.messageContent, 0, 20)} ....</a>
						    		</c:when>
						    		<c:otherwise>
						    			<a href="/manager/senderMessageDetail?messageId=${message.messageId}">${message.messageContent}</a>
						    		</c:otherwise>
						    	</c:choose>
							</td>
							<td>
							     <fmt:parseDate value="${message.createdDate}" pattern="yyyy-MM-dd'T'HH:mm" var="parsedDateTime" type="both"/>
							     <fmt:formatDate value="${parsedDateTime}" pattern="yy-MM-dd HH:mm"/>
							</td>
					    </tr>
					    </c:forEach>

					    </tbody>					    					    
					</table>
						<button onclick="deleteMessage()" class="btn btn-outline-danger">
					        <span>삭제</span>
					    </button>
        	  </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        @2022 ChoongAng University. All Rights Reserved.
                    </footer>    
        </div>
    </div>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>