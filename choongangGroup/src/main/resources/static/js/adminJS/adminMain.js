	// 페이지 로드 완료되면 실행될 function
	document.addEventListener("DOMContentLoaded", function(){
		memberList(1);
	});
	
	// 과제 list 요청 function(ajax)
	function memberList(pageNum) {
		
		var ajaxAppend = document.getElementById("ajaxAppend");
		var pageNation = document.getElementById("ajaxPagination");
		var ajaxTotalCount = document.getElementById("totalCount");
		
		
		// 과제 list 요청 (page, totalPage, totalCount, 신청한 강의 table 정보(join report))
		$.ajax({
			type: "POST",
			url: "/admin/memberPaging",
			data: { // 서버에 보낼 data
				pageNum : pageNum // pageNum 은 함수 showReport(parameter) 의 파라미터로 받음
				},
			dataType: 'json', // 서버로부터 받을 data 의 형식
			success: function(data) {
					console.log(data);
					// append 전 요소 내용 비우기
					ajaxAppend.textContent = "";
					ajaxTotalCount.textContent = "";
					// 해당 강의를 듣는 학생 count(ApplicationLec find by lecture_id)
					ajaxTotalCount.append(data.totalCount);
					//강의별 학생의 report list 정보 출력
					$.each(data.memberPaging, function(index, item) {
						// Member목록 출력 append str
						var appStr = '<tr>' +
						//'<tr><td><div class="form-check">' + 
						// 			 '<input class="form-check-input" type="checkbox" name="CheckBox" value="' + item.userid + '" id="check'+ index +'">' +
						// 			 '<input type="hidden" id="hiddenId' + index + '" name="hiddenId" value="'+ item.userid +'">'+
						//      		 '<label class="form-check-label" for="flexCheckDefault"></label></div></td>'+
									 '<td>' + item.userid + '</td>' + 
									 '<td>' + item.name + '</td>' + 
									 '<td>' + item.dname + '</td>' + 
									 '<td>' + item.phone + '</td>' +
									 '<td>' + item.email + '</td></tr>';
						$("#ajaxAppend").append(appStr);
					});
					
					//report 목록 페이지 네비게이션 출력
					pageNation.textContent = "";
					var str = '<nav aria-label="..."><ul class="pagination"><li class="page-item">';
					if(data.page > 1) {
						str += '<a class="page-link" onclick="memberList('+data.page+'-1)">이전</a>';
					} else if(data.page == 1) {
						str += '<a class="page-link">이전</a>'; 
					}
					str += '</li>'
					for (var i = 1; i < data.totalPage + 1; i++) {
						str += '<li id="page-item'+i+'" class="page-item">'+
							   '<a class="page-link" onclick="memberList('+i+')">'+i+'</a></li>';
					}
					str += '<li class="page-item">';
					if(data.page < data.totalPage ) {
						str += '<a class="page-link" onclick="memberList('+data.page+'+1)">다음</a>';
					}
					if(data.page > data.totalPage - 1) {
						str += '<a class="page-link">다음</a>'
					}
					str += '</li></ul></nav>';
					
					$("#ajaxPagination").append(str);
					var currentPage = $("#currentPage").val(data.page);
			},
			error: function() {
				alert('error');
			}
		});
	}

	function deleteMember() {
		var currentPage = $("#currentPage").val()
		if($('input:checkbox[name=CheckBox]:checked').length == 0) {
			alert("적어도 한 개 이상의 계정을 선택해주세요")
			return;
		}
		var deleteIdList = new Array();
		$('input:checkbox[name=CheckBox]').each(function (index) {
				if($(this).is(":checked") == true) {
			    	deleteIdList.push($(this).val());
					console.log($(this).val());
			    }
				
		});
		console.log(deleteIdList);
				
		$.ajax({
			type: "POST",
			url: "/admin/deleteMember",
			data: {"deleteIdList" : deleteIdList},
			success: function(data) {
				alert(data);
				memberList(currentPage);
			},
			error: function(error) {
				alert(error.status);
			}
		});
	}
