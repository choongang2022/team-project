	// 페이지 로드 완료되면 실행될 function
	document.addEventListener("DOMContentLoaded", function(){
		showReport(0);
	});
	
	// 과제 list 요청 function(ajax)
	function showReport(pageNum) {
		var selLec = document.getElementById("selLec");
		var ajaxAppend = document.getElementById("ajaxAppend");
		var pageNation = document.getElementById("ajaxPagination");
		var ajaxTotalCount = document.getElementById("totalCount");
		var hiddenReportId = document.getElementById("hiddenReportId");
		//var page = document.getElementById("page");
		selLecValue = selLec.options[selLec.selectedIndex].value;
		// spring security CSRF TOKEN
		var token = $("input[name='_csrf']").val();
		var header = "X-CSRF-TOKEN";
		// 과제 list 요청 (page, totalPage, totalCount, 신청한 강의 table 정보(join report))
		$.ajax({
			type: "POST",
			url: "/professor/lecReportList",
			data: { // 서버에 보낼 data
				id : selLecValue, page : pageNum // pageNum 은 함수 showReport(parameter) 의 파라미터로 받음
				},
			dataType: 'json', // 서버로부터 받을 data 의 형식
			beforeSend : function(xhr)
			  {  
			 	 xhr.setRequestHeader(header, token);
			  },
			success: function(data) {
					console.log(data);
					// append 전 요소 내용 비우기
					ajaxAppend.textContent = "";
					ajaxTotalCount.textContent = "";
					// 해당 강의를 듣는 학생 count(ApplicationLec find by lecture_id)
					ajaxTotalCount.append(data.totalCount);
					//강의별 학생의 report list 정보 출력
					$.each(data.ALP, function(index, item) {
						// 목록 itemNumber 출력을 위한 값 setting
						var itemNumber = index + 1 + pageNum * data.pageSize;
						// 과제목록 출력 append str
						var appStr = '<tr>'+
									 '<td>' + itemNumber + '</td>'+
									 '<td><div class="form-check">';
						// report가 null인 경우 빈값 출력, 점수입력, checkbox disabled
						if(!item.report) {
							appStr += '<input class="form-check-input" type="checkbox" name="fileCheckBox" value="" id="check'+ index +'" disabled>'+
									  '<input type="hidden" id="hiddenReportId' + index + '" name="hiddenReportId" value="'+ '' +'">'+
						     		  '<label class="form-check-label" for="flexCheckDefault"></label></div></td>'+
							 		  '<td>' + item.member.userid + '</td>'+
							 		  '<td>' + item.member.name + '</td>'+
									  '<td>' + 'N' + '</td>'+
									  '<td style="min-width: 200px;">' + '-'+
									  '<input type="hidden" id="hiddenReportFile' + index + '" name="hiddenReportFile" value="'+ '' +'"></td>'+
									  '<td style="min-width: 140px;">' + '-' + '</td>'+
									  '<td><input id="score' + index + '" class="score" type="text" name="score" value="' + '' + '" disabled></td>'+
									  '<td><input id="grade' + index + '" class="grade" type="text" name="grade" value="' + '' + '" disabled></td>'+
									  '</tr>';
						} else {
							appStr += '<input class="form-check-input" type="checkbox" name="fileCheckBox" value="' + item.report.filePath + '" id="check'+ index +'">' +
									  '<input type="hidden" id="hiddenReportId' + index + '" name="hiddenReportId" value="'+ item.report.id +'">'+
						     		  '<label class="form-check-label" for="flexCheckDefault"></label></div></td>'+
							 		  '<td>' + item.member.userid + '</td>'+
							 		  '<td>' + item.member.name + '</td>'+
									  '<td>' + item.report.whether + '</td>'+
									  '<td style="min-width: 200px;">' + item.report.fileName +
									  '<input type="hidden" id="hiddenReportFile' + index + '" name="hiddenReportFile" value="'+ item.report.filePath +'"></td>'+
									  '<td style="min-width: 140px;">' + item.report.submitDate + '</td>'+
									  '<td><input id="score' + index + '" class="score" type="text" name="score" value="'+item.report.score+'"></td>'+
									  '<td><input id="grade' + index + '" class="grade" type="text" name="grade" value="'+item.report.grade+'"></td>'+
									  '</tr>';
						};
						$("#ajaxAppend").append(appStr);
					});
					
					//report 목록 페이지 네비게이션 출력
					$('input[name=page]').attr('value', data.page);
					pageNation.textContent = "";
					var str = '<nav aria-label="..."><ul class="pagination"><li class="page-item">';
					if(data.page > 0) {
						str += '<a class="page-link" onclick="showReport('+data.page+'-1)">이전</a>';
					} else if(data.page == 0) {
						str += '<a class="page-link">이전</a>'; 
					}
					str += '</li>'
					for (var i = 1; i < data.totalPage + 1; i++) {
						str += '<li id="page-item'+i+'" class="page-item" onclick="active('+i+')">'+
							   '<a class="page-link" onclick="showReport('+i+'-1)">'+i+'</a></li>';
					}
					str += '<li class="page-item">';
					if(data.page < data.totalPage - 1) {
						str += '<a class="page-link" onclick="showReport('+data.page+'+1)">다음</a>';
					}
					if(data.page > data.totalPage - 2) {
						str += '<a class="page-link">다음</a>'
					}
					str += '</li></ul></nav>';
					
					$("#ajaxPagination").append(str);
			},
			error: function() {
				alert('error');
			}
		});
	}
	
	// 과제 성적 입력 function(ajax) //입력값이 이전 정보와 동일한 경우 제외하는 logic 추가할것
	function submitScore() {
		if (!$(".score").val() || !$(".grade").val()) {
			alert("성적을 입력해주세요");
			return;
		}
		var reportUpdateDtoList = [];
		var length = $("input[name=score]").length;
		console.log(length)
		for (var i = 0; i < length; i++) {
			if($("#hiddenReportId" + i).val() != "") {
				var reportUpdateDto = new Object();
				reportUpdateDto.id    = $("#hiddenReportId" + i).val();
				reportUpdateDto.score = $("#score" + i).val();
				reportUpdateDto.grade = $("#grade" + i).val();
				reportUpdateDtoList[i] = reportUpdateDto; 
				console.log(reportUpdateDto);
			}
		}
		console.log(reportUpdateDtoList);
		$.ajax({
			type: "POST",
			url: "/professor/updateReportScore",
			data: JSON.stringify(reportUpdateDtoList),
			contentType: "application/json",
			traditional: true,
			//dataType: 'json',
			success: function() {
				alert('입력완료');
			},
			error: function() {
				alert('error');
			}
		});
	}
	
	// 선택된 과제 다운로드 function
	function downloadFileSel() {
		if($('input:checkbox[name=fileCheckBox]:checked').length == 0) {
			alert("적어도 한 개 이상의 과제를 선택해주세요")
			return;
		}
		var fileList = new Array();
		var filePath;
	    filePath = $('input:checkbox[name=fileCheckBox]:checked').val();
		console.log($('input:checkbox[name=fileCheckBox]:checked').val());
		var filePathSplit = filePath.split('_');
		console.log(filePathSplit);
		var fileName = filePathSplit[1];
		console.log(fileName);
		
		//1개만 체크되어 있으면 file 1개 다운로드
		if($('input:checkbox[name=fileCheckBox]:checked').length == 1) {
			$.ajax({
				url:"/professor/downloadOneFile",
				data:{filePath: filePath
					  },
				dataType:'text',
				success:function(data) {
					downloadFile(filePath, fileName);
					window.location.reload();
				}
			});
		} else { // 2개 이상 체크되어 있으면 압축파일 생성 후 다운로드
			$('input:checkbox[name=fileCheckBox]').each(function (index) {
				if($(this).is(":checked") == true) {
			    	fileList.push($(this).val());
					console.log($(this).val());
			    }
			});
			console.log(fileList);
			$.ajax({
				type: "POST",
				url: "/professor/createZipSel",
				data:{
					"fileList": fileList
					},
				success: function(data) {
					downloadZipFile();
				},
				error: function() {
					alert("서버에러");
				}
			});
		}
	}
	
	// 전체내려받기 function
	function downloadFileAll() {
		var selLec = document.getElementById("selLec"); 
		selLecValue = selLec.options[selLec.selectedIndex].value; // select 에 선택된 강의 id
		$.ajax({
			type: "POST",
			url: "/professor/createZipAll/" + selLecValue,
			dataType: "text",
			success: function(data) {
				console.log(data);
				if(data == "과제 파일이 존재하지 않습니다.") {
					alert(data);
					return;
				}
				downloadZipFile();
			},
			error: function() {
				alert("서버에러 zip file 생성 실패");
			}
		});
	}
	
	// zipFile 다운로드 function
	function downloadZipFile() {
		var downloadLink = document.createElement("a");
		downloadLink.href = '/professor/downloadZip'; // controller 에 download 요청
		downloadLink.download = "report.zip"; // client 에서 다운로드시 저장되는 파일 이름
		document.body.appendChild(downloadLink);
		downloadLink.click();
		document.body.removeChild(downloadLink);
	}
	
	//file 한개일 경우 파일다운로드 method
	function downloadFile(filePath, fileName) {
		var downloadLink = document.createElement("a");
		var url = '/professor/downloadOneFile?filePath=' + filePath;
		downloadLink.href = encodeURI(url); // controller 에 download 요청
		downloadLink.download = fileName; // client 에서 다운로드시 저장되는 파일 이름
		document.body.appendChild(downloadLink);
		downloadLink.click();
		document.body.removeChild(downloadLink);
	}