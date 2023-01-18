package com.oracle.choongangGroup.hs.approval;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.SecurityService;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.dto.MessageDto;
import com.oracle.choongangGroup.taewoo.repository.NoticeJpaRepository;
import com.oracle.choongangGroup.taewoo.service.MessageService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/manager")
public class ApprovalController {
	
	private final ApprovalService as;
	private final GetMember gm;
	private final NoticeJpaRepository nr;
	private final SecurityService ss;
	private final MessageService ms;
	
	
	@GetMapping("/managerMain")
	public String managerMain(Model model, @RequestParam(required = false, defaultValue = "0", value="page") int page, Pageable pageable) {
		log.info("managerMain 시작");
		String mainCheck = "1";
		
		Member member = gm.getMember();
		String userid = member.getUserid();
		// 공지사항 부분
		String noticeType = gm.getMember().getMemRole();
		String allContent = "allContent";
		
		Page<Notice> noticeList = nr.findByNoticeTypeOrNoticeType(PageRequest.of(page, 10, Sort.by(Sort.Direction.DESC,"noticeNum")), noticeType, allContent);
		model.addAttribute("noticeList", noticeList.getContent());
		
		//  쪽지함 부분
		Member member2 = ss.findByUserid(userid);
		List<MessageDto> messageList = ms.receiveMessage(member2, pageable);
		model.addAttribute("messageList", messageList);
		
		List<Approval> approvalWaitingList = null;     // 승인 대기중
		List<Approval> approvalProcessingList = null;  // 승인 진행중
		
		int waitTotal	 = as.waitTotal(userid);
		int processTotal = as.processTotal(userid);	  
		
		// 3개 까지 보여줌
		Approval approval = new Approval();
		approval.setUserid(userid);
		approval.setStart(1);
		approval.setEnd(5);
		
		approvalWaitingList = as.waitListAll(approval); // 승인 대기중
		approvalProcessingList = as.processListAll(approval); // 승인 진행중
		
		model.addAttribute("processTotal", processTotal);
		model.addAttribute("waitTotal", waitTotal);
		model.addAttribute("mainCheck", mainCheck);
		model.addAttribute("member", member);
		model.addAttribute("waitList", approvalWaitingList);
		model.addAttribute("processList", approvalProcessingList);
		return "manager/main";
	}
	
	// --------------결재메인 -----------------------
	@RequestMapping("approval")
	public String content(Model model) {
		log.info("approvalMain start...");
		
		Member member = gm.getMember();
		String userid = gm.getMember().getUserid();
		log.info(userid);
		
		List<Approval> approvalWaitingList = null;     // 승인 대기중
		List<Approval> approvalProcessingList = null;  // 승인 진행중
		List<Approval> approvalEndList = null;	   	   // 승인 완료
		
		// 결재 페이징
		int waitTotal	 = as.waitTotal(userid);	  	  // 승인 대기중
		// int processTotal = as.processTotal(userid);	  // 승인 진행중
		// int finishTotal  = as.finishTotal(userid);	  // 승인 완료
		
		// 3개 까지 보여줌
		Approval approval = new Approval();
		approval.setUserid(userid);
		approval.setStart(1);
		approval.setEnd(3);
		
		approvalWaitingList    = as.waitListAll(approval); 	  // 승인 대기중
		approvalProcessingList = as.processListAll(approval); // 승인 진행중
		approvalEndList   	   = as.endListAll(approval); 	  // 승인 완료
		
		model.addAttribute("waitList", approvalWaitingList);
		model.addAttribute("processList", approvalProcessingList);
		model.addAttribute("endList", approvalEndList);
		model.addAttribute("waitTotal", waitTotal);
		model.addAttribute("userid", userid);
		model.addAttribute("member", member);
		
		return "manager/approvalMain";
		
	}
	
	// --------------새결재폼 -----------------------
	@RequestMapping("approvalWrite")
	public String form(Model model) {
		log.info("approvalWrite start...");
		
		String userid = gm.getMember().getUserid();
		log.info(userid);
		// 결재하는 사용자의 이름 출력
		Member member = gm.getMember();
		
		MemDept memDept = new MemDept();
		memDept.setUserid(userid);
		
		MemDept apprInfo = as.findMem(memDept.getUserid());
		
		model.addAttribute("apprInfo", apprInfo);
		model.addAttribute("member", member);
		return "manager/approvalForm";
	}
	
	// --------------결재저장 -----------------------
	@PostMapping("approvalSave")
	public String save(String userid, Approval approval, HttpServletRequest request, MultipartFile file1, Model model) throws IOException, Exception {
		log.info("approvalSave start...");
		int result = 0;
		
		userid =  gm.getMember().getUserid();
		log.info(userid);
		approval.setUserid(userid);
		
		if(!file1.isEmpty()) {
			// 파일 저장
			String filePath = request.getSession().getServletContext().getRealPath("/fileUpload/hs/");
			log.info("file POST Start...");
			log.info("originalName: {}", file1.getOriginalFilename());
			log.info("size: {}", file1.getSize());
			log.info("contentType: {}", file1.getContentType());
			log.info("filePath: {}", filePath);
			String serverFileName = uploadFile(file1.getOriginalFilename(), file1.getBytes(), filePath);
			log.info("serverFileName: {}", serverFileName);
			
			approval.setFile_path(filePath);
			approval.setServer_file_name(serverFileName);
			approval.setOrg_file_name(file1.getOriginalFilename());
			
			result = as.saveAppr(approval);
			
			if(result > 0) {
				return "redirect:approval";
			} else {
				
				return "forward:approvalWrite";
			}
		} else {
			result = as.save(approval);
			
			if(result > 0) {
				return "redirect:approval";
			} else {
				
				return "forward:approvalWrite";
			}
		}	
	}
	
	// 파일 업로드 메서드
	private String uploadFile(String originalName, byte[] fileData, String filePath) throws Exception {
		// universally unique identifier (UUID).
		UUID uid = UUID.randomUUID();
		// requestPath = requestPath + "/resources/image";
		log.info("uploadFile filePath: {}",filePath);
		// Directory 생성
		File fileDirectory = new File(filePath);
		if (!fileDirectory.exists()) {
			fileDirectory.mkdirs(); // mkdir 신규 폴더 생성
			log.info("업로드용 폴더 생성 : {}", filePath);
		}
		
		String serverFileName = uid.toString()+"_"+originalName;
		log.info("serverFileName: {}", serverFileName);
		File target = new File(filePath, serverFileName);
		// File target = new File(requestPath, savedName);
		// File Upload -> uplaodPath / UUID+_+originalName
		FileCopyUtils.copy(fileData, target); // org.springframework.util.FileCopyUtils
		
		return serverFileName;
	}
	
	// --------------결재대기중 목록 이동 -----------------------
	@GetMapping("approvalWait")
	public String wait(String userid, String currentPage, Model model) {
		log.info("approvalWait start...");
		Member member = gm.getMember();
		
		
		userid =  gm.getMember().getUserid();
		log.info(userid);
		Approval approval = new Approval();
		approval.setUserid(userid);
		
		//페이징
		int waitTotal = as.waitTotal(userid);	  // 승인 대기중
		
		Paging page = new Paging(waitTotal, currentPage);
		approval.setStart(page.getStart());
		approval.setEnd(page.getEnd());
		
		List<Approval> waitList = as.waitListAll(approval);
		log.info("waitList.size()->{}",waitList.size());
		
		model.addAttribute("waitList", waitList);
//		model.addAttribute("mem_name", mem_name);
		model.addAttribute("waitTotal", waitTotal);
		model.addAttribute("page", page);
		model.addAttribute("member", member);
		
		return "manager/approvalWaitForm";
		
	}
	
	// --------------결재대기중 상세폼이동 -----------------------
	@RequestMapping("apprWaitDetail")
	public String waitDetail(String userid, Long approval_no, Model model) {
		log.info("waitDetail start...");
		Member member = gm.getMember();
		userid =  gm.getMember().getUserid();
		log.info(userid);
		// 결재상세내용
		Approval approval = new Approval();
		approval.setUserid(userid);
		approval.setApproval_no(approval_no);
		
		Approval appr = as.waitDetail(approval);
		log.info("approval -> {}", appr.toString());
		
		// 중간 + 최종 결재자 + 기안자 상세정보
		String mid_approver_no = null;
		String fin_approver_no = null;
		String approver = null;
		
		MemDept midapprvo = null;
		MemDept finapprvo = null;
		MemDept memDept   = null;
		
		if(appr.getMid_approver() != null && !"".equals(appr.getMid_approver())) {
			mid_approver_no = appr.getMid_approver();
			midapprvo = as.findMem(mid_approver_no);
			appr.setMidapprvo(midapprvo);
		}
		
		if(appr.getFin_approver() != null && !"".equals(appr.getFin_approver())) {
			fin_approver_no = appr.getFin_approver();
			finapprvo = as.findMem(fin_approver_no);
			appr.setFinapprvo(finapprvo);
		}
		
		if(appr.getUserid() != null && !"".equals(appr.getUserid())) {
			approver = appr.getUserid();
			memDept = as.findMem(approver);
			appr.setMemDept(memDept);
		}
		
		log.info("appr mid->{}",appr.getMidapprvo().getDname());
		log.info("appr fin->{}",appr.getFinapprvo().getDname());

		model.addAttribute("appr", appr);
		model.addAttribute("userid", userid);
		model.addAttribute("member", member);
		return "manager/approvalWaitDetail";
	}
	
	// --------------기안 진행 목록 이동 -----------------------
	@GetMapping("approvalProcess")
	public String process(String currentPage, Model model) {
		log.info("approvalProcess start...");
		Member member = gm.getMember();
		String userid = gm.getMember().getUserid();
		log.info(userid);
		Approval approval = new Approval();
		approval.setUserid(userid);
		
		//페이징
		int processTotal = as.processTotal(userid);
		
		Paging page = new Paging(processTotal, currentPage);
		approval.setStart(page.getStart());
		approval.setEnd(page.getEnd());
		
		List<Approval> processList = as.processListAll(approval);
		
		log.info("processList.size()->{}",processList.size());
		
		model.addAttribute("processList", processList);
//		model.addAttribute("mem_name", mem_name);
		model.addAttribute("processTotal", processTotal);
		model.addAttribute("page", page);
		model.addAttribute("member", member);
		
		return "manager/approvalProcessForm";
	}
	
	// --------------기안진행 상세폼이동 -----------------------
	@RequestMapping("apprProcessDetail")
	public String detail(Long approval_no, Model model) {
		log.info("ProcessDetail start...");
		Member member = gm.getMember();
		String userid = gm.getMember().getUserid();
		log.info(userid);
		// 결재하는 사용자의 이름 출력
		MemDept memDept = new MemDept();
		memDept.setUserid(userid);
		
		MemDept infoAppr = as.findMem(memDept.getUserid());
		
		String mem_name = infoAppr.getName();
		String dname = infoAppr.getDname();
		
		// 결재상세내용
		Approval approval = new Approval();
		approval.setUserid(userid);
		approval.setApproval_no(approval_no);
		
		Approval appr = as.processDetail(approval);
		log.info("approval -> {}", appr.toString());
		
		// 중간 + 최종 결재자 상세정보
		String mid_approver_no = null;
		String fin_approver_no = null;
		
		MemDept midapprvo = null;
		MemDept finapprvo = null;
		
		if(appr.getMid_approver() != null && !"".equals(appr.getMid_approver())) {
			mid_approver_no = appr.getMid_approver();
			midapprvo = as.findMem(mid_approver_no);
			appr.setMidapprvo(midapprvo);
		}
		
		if(appr.getFin_approver() != null && !"".equals(appr.getFin_approver())) {
			fin_approver_no = appr.getFin_approver();
			finapprvo = as.findMem(fin_approver_no);
			appr.setFinapprvo(finapprvo);
		}
		
		log.info("appr mid->{}",appr.getMidapprvo().getDname());
		log.info("appr fin->{}",appr.getFinapprvo().getDname());
		
		model.addAttribute("userid", userid);
		model.addAttribute("mem_name", mem_name);
		model.addAttribute("dname", dname);
		model.addAttribute("appr", appr);
		model.addAttribute("member", member);
		
		return "manager/approvalProcessDetail";
	}
	
	
	// --------------결재 완료 목록 이동 -----------------------
	@GetMapping("approvalEnd")
	public String end(String currentPage, Model model) {
		log.info("approvalEnd start...");
		Member member = gm.getMember();
		String userid =  gm.getMember().getUserid();
		log.info(userid);
		//페이징
		int endTotal	 = as.finishTotal(userid);  // 승인 완료
		
		Paging page = new Paging(endTotal, currentPage);
		Approval approval = new Approval();
		approval.setStart(page.getStart());
		approval.setEnd(page.getEnd());
		approval.setUserid(userid);
		
		List<Approval> endList = as.endListAll(approval);
		log.info("endList.size()->{}",endList.size());
		
		model.addAttribute("endList", endList);
		model.addAttribute("endTotal", endTotal);
//		model.addAttribute("mem_name", mem_name);
		model.addAttribute("page", page);
		model.addAttribute("member", member);
		return "manager/approvalEndForm";
		
	}
	
	// --------------결재 완료 상세폼이동 -----------------------
	@RequestMapping("apprEndDetail")
	public String finishDetail(Long approval_no, Model model) {
		log.info("finishDetail start...");
		Member member = gm.getMember();
		String userid =  gm.getMember().getUserid();
		log.info(userid);
		// 결재상세내용
		Approval approval = new Approval();
		approval.setUserid(userid);
		approval.setApproval_no(approval_no);
		
		Approval appr = as.finishDetail(approval);
		log.info("approval -> {}", appr.toString());
		
		// 중간 + 최종 결재자 + 기안자 상세정보
		String mid_approver_no = null;
		String fin_approver_no = null;
		String approver = null;
		
		MemDept midapprvo = null;
		MemDept finapprvo = null;
		MemDept memDept   = null;
		
		if(appr.getMid_approver() != null && !"".equals(appr.getMid_approver())) {
			mid_approver_no = appr.getMid_approver();
			midapprvo = as.findMem(mid_approver_no);
			appr.setMidapprvo(midapprvo);
		}
		
		if(appr.getFin_approver() != null && !"".equals(appr.getFin_approver())) {
			fin_approver_no = appr.getFin_approver();
			finapprvo = as.findMem(fin_approver_no);
			appr.setFinapprvo(finapprvo);
		}
		
		if(appr.getUserid() != null && !"".equals(appr.getUserid())) {
			approver = appr.getUserid();
			memDept = as.findMem(approver);
			appr.setMemDept(memDept);
		}
		
		log.info("appr mid->{}",appr.getMidapprvo().getDname());
		log.info("appr fin->{}",appr.getFinapprvo().getDname());

		model.addAttribute("appr", appr);
		model.addAttribute("member", member);
		
		return "manager/approvalEndDetail";
	}
}
