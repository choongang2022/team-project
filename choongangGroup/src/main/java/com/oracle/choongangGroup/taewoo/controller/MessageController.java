package com.oracle.choongangGroup.taewoo.controller;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.SecurityService;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.taewoo.domain.Message;
import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.dto.MessageDto;
import com.oracle.choongangGroup.taewoo.service.MessageService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(value = "/manager")
public class MessageController {

	private final MessageService messageService;
	private final SecurityService securityService;
	private final GetMember getMember;

	// 쪽지쓰기 화면
	@GetMapping(value = "/messageWriteForm")
	public String sendMessage(MessageDto messageDto, Model model) {
		log.info("MessageController sendMessage Start....");
		Member member = getMember.getMember();
		model.addAttribute("member", member);
		return "/manager/message/createMessageForm";
	}

	// 쪽지작성
	@PostMapping(value = "messageSave")
	public String messageSave(MessageDto messageDto) {
		log.info("MessageController messageSave Start....");
		String userid = getMember.getMember().getUserid();
		String name = getMember.getMember().getName();
		System.out.println(messageDto.toString());
		System.out.println(messageDto.getReceiverUserid());
		System.out.println(messageDto.getSenderUserid());
		messageDto.setSenderUserid(userid);
		messageDto.setSenderName(name);

		messageService.write(messageDto);

		return "redirect:/manager/message/messageList";
	}

	// 받은편지함 확인
	@GetMapping(value = "/message/messageList")
	public String receiveMessageList(Model model, Pageable pageable ) {
		log.info("MessageController receiveMessageList Start....");
		Member member = getMember.getMember();
		String userid = getMember.getMember().getUserid();
		Member member2 = securityService.findByUserid(userid);
		List<MessageDto> messageList = messageService.receiveMessage(member2, pageable);
		System.out.println(messageList.size());
		System.out.println(messageList.toString());
		model.addAttribute("messageList", messageList);
		model.addAttribute("member", member);

		return "/manager/message/messageList";
	}
	
	// 보낸편지함 확인
	@GetMapping(value = "/message/senderMessageList")
	public String senderMessageList(Model model, Pageable pageable ) {
		log.info("MessageController senderMessageList Start....");
		Member member = getMember.getMember();
		String userid = getMember.getMember().getUserid();
		Member member2 = securityService.findByUserid(userid);
		List<MessageDto> messageList = messageService.senderMessage(member2, pageable);
		System.out.println(messageList.size());
		System.out.println(messageList.toString());
		model.addAttribute("messageList", messageList);
		model.addAttribute("member", member);

		return "/manager/message/senderMessageList";
	}
	
	//받은 쪽지 삭제
	@RequestMapping(value = "/messageDelete")
	public String messageDelete(@RequestParam(value = "valueArr[]") ArrayList<Long> valueArr) {
		System.out.println("messageDelete start....");
		Member member = getMember.getMember();
		System.out.println(valueArr.size());
		System.out.println(valueArr);
		for(int i = 0; i< valueArr.size(); i++) {
			System.out.println(valueArr.get(i));
			int result = messageService.delete(valueArr.get(i), member);
			System.out.println(result);
		}
		return "redirect:/manager/message/messageList";
	}
	
	// 개별 삭제 ( 받은 쪽지)
	@RequestMapping(value = "/messageDeleteOne")
	public String messageDeleteOne(Message message) {
		System.out.println("messageDeleteOne start....");
		Member member = getMember.getMember();
		System.out.println("message.getMessageId() ->" + message.getMessageId());
		Long messageId = message.getMessageId();
		
		messageService.delete(messageId, member);
		
		return "redirect:/manager/message/messageList";
	}
	
	//보낸 쪽지 삭제
	@RequestMapping(value = "/senderMessageDelete")
	public String senderMessageDelete(@RequestParam(value = "valueArr[]") ArrayList<Long> valueArr) {
		System.out.println("senderMessageDelete start....");
		System.out.println(valueArr.size());
		System.out.println(valueArr);
		Member member = getMember.getMember();
		for(int i = 0; i< valueArr.size(); i++) {
			System.out.println(valueArr.get(i));
			int result = messageService.senderDelete(valueArr.get(i), member);
			System.out.println(result);
		}
		return "redirect:/manager/message/senderMessageList";
	}
	
	// 개별 삭제 ( 보낸 쪽지)
	@RequestMapping(value = "/SendermessageDeleteOne")
	public String senderMessageDeleteOne(Message message) {
		System.out.println("messageDeleteOne start....");
		Member member = getMember.getMember();
		System.out.println("message.getMessageId() ->" + message.getMessageId());
		Long messageId = message.getMessageId();
		
		messageService.senderDelete(messageId, member);
		
		return "redirect:/manager/message/senderMessageList";
	}

	
	// 상세 쪽지화면
	@RequestMapping(value = "/messageDetail")
	public String messageDetail(@RequestParam Long messageId, Model model) {
		log.info("messageDetail start....");
		Member member = getMember.getMember();
		Message message = messageService.Detail(messageId);
		model.addAttribute("member",member);
		model.addAttribute("message", message);
		return "/manager/message/messageDetail";
	}
	
	// 상세 쪽지화면
	@RequestMapping(value = "/senderMessageDetail")
	public String SenderMessageDetail(@RequestParam Long messageId, Model model) {
		log.info("messageDetail start....");
		Member member = getMember.getMember();
		Message message = messageService.Detail(messageId);
		model.addAttribute("member",member);
		model.addAttribute("message", message);
		return "/manager/message/SenderMessageDetail";
	}
	
}
