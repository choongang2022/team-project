package com.oracle.choongangGroup.changhun.address;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.hibernate.validator.internal.util.privilegedactions.GetAnnotationAttribute;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.JPA.PhoneLike;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/manager")
public class AddressController {
	
	public final GetMember getMember;
	public final MemberRepository memberRepository;
	public final AddressRepository addressRepository;
	public final AddressService addressService;
	
//	@RequestMapping(value = "/addressForm")
//	public String addressForm(Model model) {
//		
//		List<Member> addressList = addressService.findByAddress();
//		
//		
//		log.info("addressForm addressList.size() -> {}" , addressList.size());
//		
//		model.addAttribute("addressList",addressList);
//		
//		return "manager/addressForm";
//	}
	
	@RequestMapping(value = "/addressForm")
	public String addressForm(Model model,
			 				  @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		
		Page<Member> addressList = memberRepository.findAll(PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"dept_deptno")));
		
		int totalPage = addressList.getTotalPages();
		
		Member member = getMember.getMember();
		
		model.addAttribute("member", member);
		model.addAttribute("page", page);
		model.addAttribute("totalPage", totalPage);
		model.addAttribute("addressList",addressList.getContent());
		
		return "manager/addressForm";
	}
	
//	@RequestMapping(value = "/myLikeAddress")
//	public String likeAddress(HttpSession session,Model model) {
//		
//		String userid = "18301001";
//		
//		List<PhoneLike> likeList = addressService.likeAddress(userid);
//		
//		model.addAttribute("likeList",likeList);
//		
//		return "manager/addressLike";
//	}
	@RequestMapping(value = "/myLikeAddress")
	public String likeAddress(Model model,
							  @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		Member member = getMember.getMember();
		String userid = member.getUserid();
		
		
//		String userid = "18301001";
		
		Page<PhoneLike> like = addressRepository.findByMyUserid(userid, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"member.name")));
		
		int totalPage = like.getTotalPages();
		
		System.out.println("totalpage -> " + totalPage);
		
		
		model.addAttribute("member", member);
		model.addAttribute("page", page);
		model.addAttribute("totalPage", totalPage);
		model.addAttribute("likeList",like.getContent());
		
		return "manager/addressLike";
	}
	
	@RequestMapping(value = "/searchAddress")
	public String searchAddress(Model model,HttpServletRequest request,
						@RequestParam(value = "search") String name,
			  			@RequestParam(required = false, defaultValue = "0", value="page") int page) {
		
	Page<Member> addressList = null;
	
	Member member = getMember.getMember();
	
	if(name == null || name.equals("")) {
		addressList = memberRepository.findAll(PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"name")));
	} else {
		addressList = memberRepository.findByNameContaining(name, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"name")));
	}
	
	int totalPage = addressList.getTotalPages();
	
	System.out.println("totalpage -> " + totalPage);
	
	model.addAttribute("member", member);
	model.addAttribute("page", page);
	model.addAttribute("totalPage", totalPage);
	model.addAttribute("addressList",addressList.getContent());
	
	return "manager/addressForm";
	}

}
