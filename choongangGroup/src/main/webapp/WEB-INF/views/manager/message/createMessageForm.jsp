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
<script type="text/javascript">

	//주소록 리스트
	function addressList(){
		alert("주소록 조회");
		$.ajax({
				url : "/manager/apprList",
				dataType:'json',
				success: function(data){
					alert('success....');
					var jsonStr = JSON.stringify(data);
					alert("jsonStr->"+jsonStr);
					var html = "";
					if(data.length > 0) {
						$.each(data, function(index, obj){ 
					  			html+="<tr>";
					  	  		html+="<td>"+obj.name+"</td>";
					  	  		html+="<td>"+obj.dname+"</td>";
					  	  		html+="<td>"+obj.position+"</td>";
					  	  		html+="<td>"+obj.phone+"</td>";
					  	  		html+="<td>";
					  	  		html+="<input type='radio' name='radioBox' class='"+ index + "' value='"+obj.userid+','+obj.name+"' required='required'>";
					  	  		html+="</td>";
					  	  		html+="</tr>";
					  		});
							
					  		$("#ajaxAddressList").html(html);
						}
		  		},
				error:function(){
					alert("error");
				}
		});
	}
	
	// 주소록 정보 넣기
	function selectUser(){
		var userInfo = $('input:radio[name="radioBox"]:checked').val();
		var userid = userInfo.split(',')[0];
		var name = userInfo.split(',')[1];
		$('input[name=receiverUserid]').attr('value', userid);
		$('input[name=receiverName]').attr('value', name);
		$('#exampleModal').modal('hide');
	}
	
	
	

</script>
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
		<header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/" class="navbar-brand"> <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
			<use xlink:href="#bootstrap"></use> </svg>
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
	<div class="container-fluid w-100"
		style="background-color: rgb(214, 225, 237)">
		<div class="row">
			<!-- content header -->
			<jsp:include page="../contentHeader.jsp"></jsp:include>
					
					<!-- card header -->
					<div
						class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold"
						style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>쪽지 <i
							class="bi bi-chevron-right"></i> 쪽지 작성
					</div>
					<!-- card content -->
					<div class="col-12 rounded-bottom overflow-auto bg-light p-3"
						style="min-height: 550px;">
						<h3>쪽지 작성</h3>
						<hr>
						<input type="hidden" id=userid name="userid" value="${member.userid}">
						<form action="messageSave" method="post">
							<div>
								<label class="form-label">받는 사람</label>
								<input type="hidden" name="senderUserid" id="senderUserid" value="${member.userid}">
								<input type="hidden" name="senderName" id="senderName" value="${member.name}">
								<input type="hidden" name="receiverUserid" id="receiverUserid"> 
								<input type="text" name="receiverName" id="receiverName" readonly="readonly">
								<!-- Button trigger modal -->
								<button type="button" class="btn btn-primary"
									data-bs-toggle="modal" data-bs-target="#exampleModal"
									onclick="addressList()">주소록</button>
							</div>
								<!-- =============Modal Start==================== -->
								<div class="modal fade" id="exampleModal" tabindex="-1"
									aria-labelledby="exampleModalLabel" aria-hidden="true">
									<div class="modal-dialog">
										<div class="modal-content">
											<div class="modal-header">
												<h5 class="modal-title" id="exampleModalLabel">Modal
													title</h5>
												<button type="button" class="btn-close"
													data-bs-dismiss="modal" aria-label="Close"></button>
											</div>
											<div class="modal-body">
												<div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;">

												<table class="table table-hover">
													<thead>
														<tr>
															<th>이름</th>
															<th>부서</th>
															<th>직위</th>
															<th>연락처</th>
															<th>선택</th>
														</tr>
													</thead>
													<tbody id="ajaxAddressList">
													</tbody>
												</table>
												</div>
											</div>
											<div class="modal-footer">
												<button type="button" class="btn btn-secondary"
														data-bs-dismiss="modal">취소</button>
												<button type="button" class="btn btn-primary" onclick="selectUser()">등록</button>
											</div>
										</div>
									</div>
								</div>
									<!-- =================Modal end====================== -->
							<div style="margin: 10px;">
								<label for="exampleFormControlInput1" class="form-label">글제목</label>
								<input type="text" class="form-control"
									   id="messageTitle exampleFormControlInput1" name="messageTitle"
									   placeholder="제목을 입력하세요." required="required">
							</div>
							<div style="margin: 10px;">
								<label for="exampleFormControlTextarea1" class="form-label">내용</label>
								<textarea class="form-control" rows="3"
									      id="messageContent exampleFormControlTextarea1"
										  name="messageContent" style="height: 300px;" required="required"></textarea>
							</div>
							<div style="margin: 10px;">
								<button type="submit" class="btn btn-outline-primary">등록</button>
							</div>
						</form>
					</div>
				</div>
					<!-- footer -->
					<footer class="col-12" style="height: 60px;"> @2022 ChoongAng University. All Rights Reserved. </footer>
		</div>
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<!-- JS -->
	<script src="/js/main.js"></script>
</body>
</html>