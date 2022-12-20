package com.oracle.choongangGroup.taewoo.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.dto.NoticeDto;
import com.oracle.choongangGroup.taewoo.repository.NoticeJpaRepository;
import com.oracle.choongangGroup.taewoo.service.NoticeService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
public class NoticeController {

	private final NoticeService noticeService;
	private final NoticeJpaRepository noticeJpaRepository;
	private final GetMember getMember;
		
	//공지사항 List
	@GetMapping(value = "/notice/noticeList")
	@PreAuthorize("isAuthenticated()")
	public String listPage(Model model,
						   @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		String NoticeType = getMember.getMember().getMemRole();
		String Student = "ROLE_STUDENT";
		String Professor = "ROLE_PROFESSOR";
		String Allcontent = "allContent";
		System.out.println(NoticeType);
		
		if(NoticeType.equals(Student)) {
			System.out.println("Student Start....");
			Page<Notice> noticeList = noticeJpaRepository.findByNoticeTypeOrNoticeType(PageRequest.of(page, 10, Sort.by(Sort.Direction.DESC,"noticeNum")), NoticeType, Allcontent);
			int noticeTotal = noticeList.getTotalPages();
			Member member = getMember.getMember();
			model.addAttribute("member" , member);
			model.addAttribute("page",page);
			model.addAttribute("noticeTotal", noticeTotal);
			model.addAttribute("noticeList", noticeList.getContent());
			
			return "/student/studentNoticeList";

		} else if(NoticeType.equals(Professor)){
			System.out.println("Professor Start....");
			Page<Notice> noticeList = noticeJpaRepository.findByNoticeTypeOrNoticeType(PageRequest.of(page, 10, Sort.by(Sort.Direction.DESC,"noticeNum")), NoticeType, Allcontent);
			int noticeTotal = noticeList.getTotalPages();
			Member member = getMember.getMember();
			model.addAttribute("member" , member);
			model.addAttribute("page",page);
			model.addAttribute("noticeTotal", noticeTotal);
			model.addAttribute("noticeList", noticeList.getContent());
			
			return "/professor/professorNoticeList";		
		}
		
		else {
				System.out.println("manager Start....");
			Page<Notice> noticeList = noticeJpaRepository.findAll(PageRequest.of(page, 10, Sort.by(Sort.Direction.DESC,"noticeNum")));
			int noticeTotal = noticeList.getTotalPages();
			Member member = getMember.getMember();
			model.addAttribute("member" , member);
			model.addAttribute("page",page);
			model.addAttribute("noticeTotal", noticeTotal);
			model.addAttribute("noticeList", noticeList.getContent());
			
			return "/manager/notice/noticeList";
		}
	}
	
	// 검색 기능
	@RequestMapping(value = "/notice/search")
	@PreAuthorize("isAuthenticated()")
	public String SearchNotice(Model model, String keyword) {
		Member member = getMember.getMember();
		log.info("keyword --> {}", keyword);
		List<Notice> searchNotice = noticeService.searchNotice(keyword);
		String msg = "";
		if(searchNotice == null) {
			msg += "다시 입력해주세요";
		}
		model.addAttribute(member);
		model.addAttribute("msg",msg);
		model.addAttribute("noticeList",searchNotice);
		return "/manager/notice/noticeList";
	}
	
	
	// 공지사항 작성 화면
	@GetMapping(value = "/manager/noticeWrite")
	@Secured("ROLE_MANAGER")
	public String createForm(Model model) {
		System.out.println("NoticeController createForm Start....");
		Member member = getMember.getMember();
		model.addAttribute("member" , member);
		return "/manager/notice/createNoticeForm";
	}
	
	// 공지사항 작성
	@PostMapping(value = "/manager/noticeSave")
	@Secured("ROLE_MANAGER")
	public String create(NoticeDto noticeDto, @RequestParam String writerUserid) {
		log.info("NoticeController create start....");
		System.out.println(writerUserid);
		noticeDto.setWriterUserid(writerUserid);
		
		noticeService.write(noticeDto, writerUserid);
		return "redirect:/notice/noticeList";
	}
	
	// 상세화면
	@RequestMapping(value = "/noticeDetail")
	@PreAuthorize("isAuthenticated()")
	public String detail(@RequestParam Long noticeNum, Model model, HttpServletRequest request, HttpServletResponse response, NoticeDto noticeDto) {
		log.info("Detail start...");
		String NoticeType = getMember.getMember().getMemRole();
		String Student = "ROLE_STUDENT";
		String Professor = "ROLE_PROFESSOR";
		if(NoticeType.equals(Student)) {
			System.out.println("noticeNum -> " + noticeNum);		
			Member member = getMember.getMember();
			Notice notice = noticeService.findById(noticeNum);
			model.addAttribute("member" , member);
			model.addAttribute("notice", notice );
			noticeService.updateHit(noticeNum,request,response);
			return "/student/studentNoticeDetail";
			
		} else if(NoticeType.equals(Professor)) {
			System.out.println("noticeNum -> " + noticeNum);		
			Member member = getMember.getMember();
			Notice notice = noticeService.findById(noticeNum);
			model.addAttribute("member" , member);
			model.addAttribute("notice", notice );
			noticeService.updateHit(noticeNum,request,response);
			return "/professor/professorNoticeDetail";
			
		} else {
			
			System.out.println("noticeNum -> " + noticeNum);		
			Member member = getMember.getMember();
			Notice notice = noticeService.findById(noticeNum);
			model.addAttribute("member" , member);
			model.addAttribute("notice", notice );
			noticeService.updateHit(noticeNum,request,response);
			return "/manager/notice/noticeDetail";
		}

	}
	
//	// 글 수정	
//	@RequestMapping(value = "/manager/updateNotice")
//	@Secured("ROLE_MANAGER")
//	public String NoticeUpdate(NoticeDto noticeDto) {
//		String writerUserid = getMember.getMember().getUserid();
//		System.out.println("start");
//		System.out.println(noticeDto.toString());
//		System.out.println(noticeDto.getNoticeTitle());
//		System.out.println(noticeDto.getNoticeContent());
//		noticeDto.setWriterUserid(writerUserid);	
//		noticeService.update(noticeDto, writerUserid);
//		return "/manager/notice/noticeDetail";
//	}
	
	// 글 삭제
	@RequestMapping(value = "/manager/deleteNotice")
	@Secured("ROLE_MANAGER")
	public String NoticeDelete(Notice notice) {
		System.out.println("NoticeDelete start....");
		System.out.println("notice.getNoticeNum() ->" + notice.getNoticeNum());
		
		noticeJpaRepository.delete(notice);
		
		return "redirect:/notice/noticeList";
	}
	
	
}
