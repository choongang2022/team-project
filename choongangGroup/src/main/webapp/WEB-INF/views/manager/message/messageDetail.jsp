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
	function writeMessage(){
		alert("답장보내기 시작");
		var vsenderUserid = $("#sender").val();
		var vreceiverUserid = $("#receiver").val();
		var vsenderName = $("#senderName").val();
		var vmessageTitle1 = $("#messageTitle1").val();
		var vmessageContent1 = $("#messageContent1").val();
		console.log("vsenderUserid -->" + vsenderUserid);
		console.log("vreceiverUserid -->" + vreceiverUserid);
		console.log("vsenderName -->" + vsenderName);
		console.log("vmessageTitle1 -->" + vmessageTitle1);
		console.log("vmessageContent1 -->" + vmessageContent1);
		
		$.ajax({
			url : "/manager/messageSave",
			type : "POST",
			data : { senderUserid : vsenderUserid , receiverUserid : vreceiverUserid , senderName : vsenderName, messageTitle : vmessageTitle1 , messageContent : vmessageContent1 },
			success : function(){
				alert("전송 성공!");
				$('#staticBackdrop').modal('hide');
			}
			
		})


	}
	
	function updateNotice(){
		alert("수정완료!");
		var vnoticeNum = $("#noticeNum").val();
		var vnoticeTitle = $("#noticeTitle2").val();
		var vnoticeContent = $("#noticeContent2").val();
		var vnoticeHit = $("#noticeHit").val();
			
		console.log("vnoticeNum -> " + vnoticeNum);
		console.log("vnoticeTitle -> " + vnoticeTitle);
		console.log("vnoticeNum -> " + vnoticeContent);
		
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
			data	 : { noticeNum : vnoticeNum , noticeTitle : vnoticeTitle, noticeContent : vnoticeContent, noticeHit : vnoticeHit },
			dataType : 'text',
			success	 : function(data){
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
	function deleteMessage(){
		console.log("삭제 시작");
		var dmessageId = $("#messageId").val();
		console.log("dnoticeNum -> " + dmessageId);
		
		$.ajax({
			url 	: "/manager/messageDeleteOne",
			data	: {messageId : dmessageId},
			success : function(data){
				alert("삭제 되었습니다.");
				location.href = "/manager/message/messageList";
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
                    <a href="/manager/message/messageList" class="nav__logo">쪽지함</a>
                </div>
                <div class="nav__list">
                    <a href="/manager/messageWriteForm" class="nav__link active">
                        <ion-icon name="chatbubbles-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">쪽지보내기</span>
                    </a>
                    <a href="/manager/message/messageList" class="nav__link">
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
            
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i><a style="text-decoration: none; color: white;"  href="/manager/message/messageList">쪽지함</a> <i class="bi bi-chevron-right"></i> <a >쪽지 내용</a>
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
		                <div class="container">
		                      	<div class="mb-3">                  		
			                      	<input id="messageId" type="hidden" value="${message.messageId}">   
			                   </div>
			                   	<div class="mb-3">
			                   		<label class="form-label">보낸 사람</label>                  		
			                      	<input id="senderName" name="senderName" type="text" class="form-control" readonly="readonly" value="${message.senderName}">   
			                   </div>                  	
		                       <div class="mb-3">
		                     		<label class="form-label">제목</label>
		                     		<input id="messageTitle" name="messageTitle" type="text" class="form-control" value="${message.messageTitle}" readonly>
		                     	</div>
		                     	<div>
		                     		<label class="form-label">내용</label>
		                     		<textarea id="messageContent" name="messageContent" class="form-control" rows="3" style="height: 300px;" readonly="readonly" >${message.messageContent}</textarea>         	
		                      	</div>
		                      	<div style="margin: 10px;">
		                      			<!-- Button trigger modal -->	
		                      			<button id="beforeButton" type="button" class="btn btn-outline-primary" data-bs-toggle="modal" data-bs-target="#staticBackdrop">답장</button>	
										<!-- Modal -->
										<div class="modal fade" id="staticBackdrop" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
										  <div class="modal-dialog">
										    <div class="modal-content">
										      <div class="modal-header">
										        <h1 class="modal-title fs-5" id="staticBackdropLabel">답장 보내기</h1>
										        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
										      </div>
										      <div class="modal-body">
										      <form class="form-signin" id="messageForm">
										        <div class="mb-3">
			                   						<label class="form-label">받는 사람</label>
			                   						<input type="hidden" id="sender" name="sender" value="${message.receiver.userid}">
			                   						<input type="hidden" id="receiver" name="receiver" value="${message.sender.userid}">                  		
			                      					<input id="senderName" name="senderName" type="text" class="form-control" readonly="readonly" value="${message.senderName}">   
			                   					</div>
			                   					<div class="mb-3">
						                     		<label class="form-label">제목</label>
						                     		<input id="messageTitle1" name="messageTitle1" type="text" class="form-control" >
						                     	</div>
						                     	<div>
						                     		<label class="form-label">내용</label>
						                     		<textarea id="messageContent1" name="messageContent1" class="form-control" rows="3" style="height: 300px;" ></textarea>         	
						                      	</div>
						                      </form>
										      </div>
										      <div class="modal-footer">
										        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
										        <button type="button" class="btn btn-primary" onclick="writeMessage()">보내기</button>
										      </div>
										    </div>
										  </div>
										</div>
		                      			
			                        	<button id="deleteButton" type="button" class="btn btn-outline-danger" onclick="deleteMessage()">삭제</button>	    
			                    </div>
		                  	 </div>
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