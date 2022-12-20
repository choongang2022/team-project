// 페이지 로드 완료되면 실행될 function
	document.addEventListener("DOMContentLoaded", function(){
		showLecList();
	});

    // 강의조회
    function showLecList() {
        var selYear  = document.getElementById("selYear");
        var selSeme  = document.getElementById("selSeme");
        var getProfName = document.getElementById("getProfName");
        selYearValue  = selYear.options[selYear.selectedIndex].value;
        selSemeValue  = selSeme.options[selSeme.selectedIndex].value;
        getProfNameValue = getProfName.value;
        console.log(selYearValue);
        console.log(selSemeValue);
        console.log(getProfNameValue);
        var ajaxAppend = document.getElementById("ajaxAppend");

        $.ajax({
            type: "POST",
			url: "/professor/lecList",
			data: { // 서버에 보낼 data
				year: selYearValue,
                semester: selSemeValue,
                profName: getProfNameValue
				},
			dataType: 'json', // 서버로부터 받을 data 의 형식
			success: function(data) {
					console.log(data);
					// append 전 요소 내용 비우기
					ajaxAppend.textContent = "";
					// 강의의 list 정보 출력
					$.each(data, function(index, item) {
                        var str = '<tr class="align-middle text-center" onclick="showPlanDetail(' + index + ')">' +
                                  '<td scope="col" style="width: 4%;">' + (index+1) + 
                                  '<input type="hidden" name="lec_id" id="lec_id' + index + '" value="' + item.lec_id + '">'+ 
                                  '<input type="hidden" name="getlec_name" id="getlec_name' + index + '" value="' + item.lec_name + '">'+ 
								  '</td>'+
                                  '<td scope="col" style="width: 15%;">' + item.major_gubun +  
                                  '<td scope="col" style="width: 9%;">' + item.lec_typecode + item.lec_id + 
                                  '<input type="hidden" name="getLecCode" id="getLecCode' + index + '" value="' + item.lec_typecode + item.lec_id + ' ' + item.lec_name + '">'+ 
								  '</td>'+
                                  '<td scope="col" style="width: 15%;">' + item.lec_name + '</td>' + 
                                  '<td scope="col" style="width: 9%;">' + item.lec_type + '</td>' + 
                                  '<td scope="col" style="width: 5%;">' + item.lec_unit_score + '</td>' + 
                                  '<td scope="col" style="width: 5%;">' + item.lec_max_count + '</td>';
                        if(!item.lec_file_path || item.lec_file_path == "") {
                            str += '<td scope="col" style="width: 7%;">' + "파일없음" + '</td>';
                        } else {
                            str += '<td scope="col" style="width: 7%;">' + item.lec_file_name + '</td>';
                        }
                        str += '<td scope="col" style="width: 20%;">' + 
                               '<input class="form-control form-control-sm" id="formFileSm" type="file" name="planFile' + index +'" style="display: inline-block; width: 75%">' +
                               '<button class="btn ms-2" onclick="uploadPlanFile('+ index +')" ' + 
                               'style="font-size: small; display: inline-block; height: 30px; width: 70px; border: 1px solid #ced4da; background-color: #dde0e3">업로드</button>' + 
                               '</td></tr>';
                        $(ajaxAppend).append(str);
                    });
                },
                error: function() {
                    alert("서버에러");
                }
        });
    }
    // 강의계획서 작성 부분에 data 출력
    function showPlanDetail(index) {
        const id = $("input#lec_id" + index).val();
        const lecName = $("input#getlec_name" + index).val();
        const getLecCode = $("input#getLecCode"+ index).val();
        $.ajax({
			type: "POST",
			url: "/professor/showPlanDetail",
			dataType: "json",
			data: {
				lecId: id
			},
			success: function(data) {
                console.log(data);
                $("#detailId").val(id);
                readonly();
                if (!data.lec_plan) {
                    $("#selectedLec").       val("선택된 강의 : " + getLecCode);
                    $("#lec_name").          val(lecName);
                    $("#plan_goal").         val("");
                    $("#plan_midterm_ratio").val("");
                    $("#plan_final_ratio").  val("");
                    $("#plan_report_ratio"). val("");
                    $("#plan_attendance").   val("");
                    $("#plan_way").          val("");
                    $("#book_name").         val("");
                    $("#book_author").       val("");
                    $("#book_publisher").    val("");
                    $("#book_year").         val("");
                    $("#plan_eval_detail1"). val("");
                    $("#plan_eval_detail2"). val("");
                    for (let i = 0; i < 15; i++) {
                        $("#week_detail"+ i ).val("");
                    }
                } else {
                    $("#selectedLec").       val("선택된 강의 : " + getLecCode);
                    $("#lec_name").          val(lecName);
                    $("#plan_goal").         val(data.lec_plan.plan_goal);
                    $("#plan_midterm_ratio").val(data.lec_plan.plan_midterm_ratio);
                    $("#plan_final_ratio").  val(data.lec_plan.plan_final_ratio);
                    $("#plan_report_ratio"). val(data.lec_plan.plan_report_ratio);
                    $("#plan_attendance").   val(data.lec_plan.plan_attendance);
                    $("#plan_way").          val(data.lec_plan.plan_way);
                    $("#book_name").         val(data.lec_plan.book_name);
                    $("#book_author").       val(data.lec_plan.book_author);
                    $("#book_publisher").    val(data.lec_plan.book_publisher);
                    $("#book_year").         val(data.lec_plan.book_year);
                    $("#plan_eval_detail1"). val(data.lec_plan.plan_eval_detail1);
                    $("#plan_eval_detail2"). val(data.lec_plan.plan_eval_detail2);
                    $.each(data.lec_plan_weekList, function (index, item) { 
                        $("#week_detail"+ index ).val(item.week_detail);
                    });
                }
			},
			error: function() {
				alert("서버에러");
			}
		});
    }
    //강의계획서 db 입력 ,수정 (controller에서 조건에 따라 입력 수정 분기)
    function insertOrUpdatePlan() {
        if ($("#selectedLec").val() == "선택된 강의 없음") {
            alert("선택된 강의가 없습니다.\n강의를 선택해주세요.");
            return;
        }
        if (!$("#plan_goal").         val() ||
            !$("#plan_final_ratio").  val() ||
            !$("#plan_report_ratio"). val() ||
            !$("#plan_midterm_ratio").val() ||
            !$("#plan_attendance").   val() ||
            !$("#plan_way").          val() ||
            !$("#book_name").         val() ||
            !$("#book_author").       val() ||
            !$("#book_publisher").    val() ||
            !$("#book_year").         val() ||
            !$("#plan_eval_detail1"). val() ||
            !$("#plan_eval_detail2"). val()
           ) {
            if (!confirm("입력되지 않은 항목이 있습니다.\n무시하고 강의계획서 내용을 입력하시겠습니까?")) {
                return;
            }
        }
        readonly();
        var planDto = new Object();
        var hiddenId = $("#detailId").val();
        planDto.lec_id             = parseInt(hiddenId);
        planDto.plan_goal          = $("#plan_goal").         val();
        planDto.plan_midterm_ratio = $("#plan_midterm_ratio").val();
        planDto.plan_final_ratio   = $("#plan_final_ratio").  val();
        planDto.plan_report_ratio  = $("#plan_report_ratio"). val();
        planDto.plan_attendance    = $("#plan_attendance").   val();
        planDto.plan_way           = $("#plan_way").          val();
        planDto.book_name          = $("#book_name").         val();
        planDto.book_author        = $("#book_author").       val();
        planDto.book_publisher     = $("#book_publisher").    val();
        planDto.book_year          = $("#book_year").         val();
        planDto.plan_eval_detail1  = $("#plan_eval_detail1"). val();
        planDto.plan_eval_detail2  = $("#plan_eval_detail2"). val();
        var planWeekArray              = new Array();
        for (let i = 0; i < 15; i++) {
            planWeekArray[i] = {lec_id: parseInt(hiddenId), week: (i+1) , weekDetail: $("#week_detail"+ i ).val()};
        }
        planDto.planWeekArray = planWeekArray;
        $.ajax({
            type: "POST",
            url: "/professor/insertOrUpdatePlan",
            // contentType: "application/json",
            // traditional: true,
            // dataType: "JSON",
            data: planDto
            ,
            success: function(data) {
                console.log(data);
                if(data == 1) {
                    alert("입력성공");
                    readonly();
                } else {
                    alert("실패")
                }
            },
            error: function() {
                alert("서버에러");
            }
        });
    }
    // 강의계획서 삭제
    function deletePlan() {
        readonly();
        if ($("#selectedLec").val() == "선택된 강의 없음") {
            alert("선택된 강의가 없습니다.\n강의를 선택해주세요.");
            return;
        }
        var lec_id = parseInt($("#detailId").val());
        console.log(lec_id);

        $.ajax({
            type: "POST",
            url: "/professor/deletePlan",
            data: {lec_id: lec_id},
            success: function(data) {
                console.log(data);
                if(data == -2) {
                    alert("삭제할 강의계획서가 존재하지 않습니다.");
                } else if (data == -3) {
                    alert("강의계획서 파일 삭제 성공")
                } else if (data == 3){
					alert("강의계획서 내용 삭제 성공")
				} else {
                    alert("강의계획서 내용, 파일 삭제 성공");
                $("#plan_goal").         val("");
                $("#plan_midterm_ratio").val("");
                $("#plan_final_ratio").  val("");
                $("#plan_report_ratio"). val("");
                $("#plan_attendance").   val("");
                $("#plan_way").          val("");
                $("#book_name").         val("");
                $("#book_author").       val("");
                $("#book_publisher").    val("");
                $("#book_year").         val("");
                $("#plan_eval_detail1"). val("");
                $("#plan_eval_detail2"). val("");
                for (let i = 0; i < 15; i++) {
                    $("#week_detail"+ i ).val("");
                }
            }
            showLecList();
            },
            error: function() {
                alert("서버에러");
            }
        })
    }

    //pdf 파일 생성 및 새창에 미리보기 띄우기
    function generatePdf() {
        if ($("#selectedLec").val() == "선택된 강의 없음") {
            alert("선택된 강의가 없습니다.\n강의를 선택해주세요.");
            return;
        }
        if (!$("#plan_goal").         val() ||
            !$("#plan_final_ratio").  val() ||
            !$("#plan_report_ratio"). val() ||
            !$("#plan_midterm_ratio").val() ||
            !$("#plan_attendance").   val() ||
            !$("#plan_way").          val() ||
            !$("#book_name").         val() ||
            !$("#book_author").       val() ||
            !$("#book_publisher").    val() ||
            !$("#book_year").         val() ||
            !$("#plan_eval_detail1"). val() ||
            !$("#plan_eval_detail2"). val()
           ) {
            if (!confirm("입력되지 않은 항목이 있습니다.\n무시하고 pdf파일을 다운로드 하시겠습니까?")) {
                return;
            }
        }
        var planPdfDto = new Object();
        var weekDetail;

        planPdfDto.prof_name          = $("#profName").          val();
        planPdfDto.lec_name           = ($("#selectedLec").      val()).substring(9);
        planPdfDto.major              = $("#major_gubun").       val();
        planPdfDto.email              = $("#email").             val();
        planPdfDto.phone              = $("#phone").             val();
        planPdfDto.plan_goal          = $("#plan_goal").         val();
        planPdfDto.plan_midterm_ratio = $("#plan_midterm_ratio").val();
        planPdfDto.plan_final_ratio   = $("#plan_final_ratio").  val();
        planPdfDto.plan_report_ratio  = $("#plan_report_ratio"). val();
        planPdfDto.plan_attendance    = $("#plan_attendance").   val();
        planPdfDto.plan_way           = $("#plan_way").          val();
        planPdfDto.book_name          = $("#book_name").         val();
        planPdfDto.book_author        = $("#book_author").       val();
        planPdfDto.book_publisher     = $("#book_publisher").    val();
        planPdfDto.book_year          = $("#book_year").         val();
        planPdfDto.plan_eval_detail1  = $("#plan_eval_detail1"). val();
        planPdfDto.plan_eval_detail2  = $("#plan_eval_detail2"). val();
        for (let index = 0; index < 15; index++) {
            planPdfDto["week_detail" + (index + 1)] = $("#week_detail" + (index)). val();
        }
        console.log(planPdfDto);    

        $.ajax({
            type: "POST",
            url:'/professor/createPdf',
            data: planPdfDto,
            dataType: 'text',
            async: false,
            success: function(data) {
                console.log(data)
                var options = {
                    pdfOpenParams: {
                        navpanes: 0,
                        toolbar: 0,
                        statusbar: 0,
                        view: "FitV",
                        page: 1
                    },
                    width: "100%",
                    height: "100%",
                    forcePDFJS: true,
                    PDFJS_URL: "/js/pdfjs/web/viewer.html"
                }
                //PDFObject.embed("${contextPath }/pdf/" + data + ".pdf");
                window.open("/js/pdfjs/web/viewer.html?file=" + encodeURI("/pdf/" + data + ".pdf"));
                console.log("${contextPath }/pdf/" + data + ".pdf");
            },
            error: function(error) {
                alert(error.status + " 서버에러");
            }
        });
    }
    //강의계획서 파일 업로드
    function uploadPlanFile(index) {
        var lec_id = $("#lec_id"+index).val();
        var formData = new FormData();
        var data = {
            "lec_id": lec_id
        }
        var inputFile = $("input[name='planFile" + index + "']");
        var files = inputFile[0].files;
        console.log(files);

            formData.append("uploadFile", files[0]);
            console.log(files[0]);
        
        formData.append("data", lec_id);
        console.log(formData);
        $.ajax({
            type: "POST",
            url: "/professor/uploadPlanFile",
            processData: false,
            contentType: false,
            data: formData,
            success: function(data) {
                if (data > 0) {
                    alert("업로드 성공");
                    showLecList();
                }
            },
            error: function(error) {
                alert(error.status + " 서버에러");
            }
        });
    }


    // 편집모드
    function editorMode() {
        $("#plan_goal").         removeAttr("readonly");
        $("#plan_midterm_ratio").removeAttr("readonly");
        $("#plan_final_ratio").  removeAttr("readonly");
        $("#plan_report_ratio"). removeAttr("readonly");
        $("#plan_attendance").   removeAttr("readonly");
        $("#plan_way").          removeAttr("readonly");
        $("#book_name").         removeAttr("readonly");
        $("#book_author").       removeAttr("readonly");
        $("#book_publisher").    removeAttr("readonly");
        $("#book_year").         removeAttr("readonly");
        $("#plan_eval_detail1"). removeAttr("readonly");
        $("#plan_eval_detail2"). removeAttr("readonly");
        for (let i = 0; i < 15; i++) {
            $("#week_detail"+ i ).removeAttr("readonly");
        }
    }
    // 편집모드 해제
    function readonly() {
        $("#plan_goal").         attr("readonly", "readonly");
        $("#plan_final_ratio").  attr("readonly", "readonly");
        $("#plan_midterm_ratio").attr("readonly", "readonly");
        $("#plan_report_ratio"). attr("readonly", "readonly");
        $("#plan_attendance").   attr("readonly", "readonly");
        $("#plan_way").          attr("readonly", "readonly");
        $("#book_name").         attr("readonly", "readonly");
        $("#book_author").       attr("readonly", "readonly");
        $("#book_publisher").    attr("readonly", "readonly");
        $("#book_year").         attr("readonly", "readonly");
        $("#plan_eval_detail1"). attr("readonly", "readonly");
        $("#plan_eval_detail2"). attr("readonly", "readonly");
        for (let i = 0; i < 15; i++) {
            $("#week_detail"+ i ).attr("readonly", "readonly");
        }
    }