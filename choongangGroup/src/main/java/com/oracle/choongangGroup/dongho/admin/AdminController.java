package com.oracle.choongangGroup.dongho.admin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {
	private final AdminService adminService;
	
	@GetMapping("/main")
	public String adminMain() {
		return "/admin/adminMain";
	}
	
	@ResponseBody
	@PostMapping("/memberPaging")
	public Map<String, Object> memberPaging(int pageNum) {
		List<MemberPagingDto> memberPaging = adminService.memberPaging(pageNum);
		System.out.println(memberPaging);
		int totalCount = adminService.memberCount();
		int totalPage =(int) Math.floor(totalCount/10) +1;
		Map<String, Object> map = new HashMap<>();
		map.put("page", pageNum);
		map.put("memberPaging", memberPaging);
		map.put("totalCount", totalCount);
		map.put("totalPage", totalPage);
		return map;
	}
	
	@ResponseBody
	@PostMapping("/deleteMember")
	public int deleteMember(@RequestParam(value = "deleteIdList[]") ArrayList<String> deleteIdList) {
		int result = 0;
		result = adminService.deleteMember(deleteIdList);
		return result;
	}
}
